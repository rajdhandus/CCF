// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http_consts.h"
#include "http_parser.h"
#include "node/client_signatures.h"
#include "tls/base64.h"
#include "tls/hash.h"
#include "tls/key_pair.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <optional>
#include <string>

namespace http
{
  inline std::optional<std::vector<uint8_t>> construct_raw_signed_string(
    std::string verb,
    const std::string_view& path,
    const std::string_view& query,
    const http::HeaderMap& headers,
    const std::vector<std::string_view>& headers_to_sign)
  {
    std::string signed_string = {};
    std::string value = {};
    bool first = true;

    for (const auto f : headers_to_sign)
    {
      if (f == auth::SIGN_HEADER_REQUEST_TARGET)
      {
        // Store verb as lowercase
        std::transform(
          verb.begin(), verb.end(), verb.begin(), [](unsigned char c) {
            return std::tolower(c);
          });
        value = fmt::format("{} {}", verb, path);
        if (!query.empty())
        {
          value.append(fmt::format("?{}", query));
        }
      }
      else
      {
        const auto h = headers.find(f);
        if (h == headers.end())
        {
          LOG_FAIL_FMT("Signed header '{}' does not exist", f);
          return std::nullopt;
        }

        value = h->second;
      }

      if (!first)
      {
        signed_string.append("\n");
      }
      first = false;

      signed_string.append(f);
      signed_string.append(": ");
      signed_string.append(value);
    }

    auto ret =
      std::vector<uint8_t>({signed_string.begin(), signed_string.end()});
    return ret;
  }

  struct SigningDetails
  {
    std::vector<uint8_t> to_sign;
    std::vector<uint8_t> signature;
  };

  inline void add_digest_header(http::Request& request)
  {
    // Ensure digest is present and up-to-date
    tls::HashBytes body_digest;
    tls::do_hash(
      request.get_content_data(),
      request.get_content_length(),
      body_digest,
      MBEDTLS_MD_SHA256);
    request.set_header(
      headers::DIGEST,
      fmt::format(
        "{}={}",
        "SHA-256",
        tls::b64_from_raw(body_digest.data(), body_digest.size())));
  }

  inline void sign_request(
    http::Request& request,
    const tls::KeyPairPtr& kp,
    const std::vector<std::string_view>& headers_to_sign,
    SigningDetails* details = nullptr)
  {
    add_digest_header(request);

    const auto to_sign = construct_raw_signed_string(
      http_method_str(request.get_method()),
      request.get_path(),
      request.get_formatted_query(),
      request.get_headers(),
      headers_to_sign);

    if (!to_sign.has_value())
    {
      throw std::logic_error("Unable to sign HTTP request");
    }

    const auto signature = kp->sign(to_sign.value(), MBEDTLS_MD_SHA256);

    auto auth_value = fmt::format(
      "Signature "
      "keyId=\"ignored\",algorithm=\"{}\",headers=\"{}\",signature="
      "\"{}\"",
      auth::SIGN_ALGORITHM_SHA256,
      fmt::format("{}", fmt::join(headers_to_sign, " ")),
      tls::b64_from_raw(signature.data(), signature.size()));

    request.set_header(headers::AUTHORIZATION, auth_value);

    if (details != nullptr)
    {
      details->to_sign = to_sign.value();
      details->signature = signature;
    }
  }

  inline void sign_request(
    http::Request& request,
    const tls::KeyPairPtr& kp,
    SigningDetails* details = nullptr)
  {
    std::vector<std::string_view> headers_to_sign;
    headers_to_sign.emplace_back(auth::SIGN_HEADER_REQUEST_TARGET);
    headers_to_sign.emplace_back(headers::DIGEST);
    headers_to_sign.emplace_back(headers::CONTENT_LENGTH);

    sign_request(request, kp, headers_to_sign, details);
  }

  // Implements verification of "Signature" scheme from
  // https://tools.ietf.org/html/draft-cavage-http-signatures-12
  //
  // Tested with RequestClient in tests/infra/clients.py
  //
  // Notes:
  //    - Only supports public key crytography (i.e. no HMAC)
  //    - Only supports SHA-256 as digest algorithm
  //    - Only supports ecdsa-sha256 as signature algorithm
  //    - keyId is ignored
  class HttpSignatureVerifier
  {
  public:
    struct SignatureParams
    {
      std::string_view signature = {};
      std::string_view signature_algorithm = {};
      std::vector<std::string_view> signed_headers;
    };

    static bool parse_auth_scheme(std::string_view& auth_header_value)
    {
      auto next_space = auth_header_value.find(" ");
      if (next_space == std::string::npos)
      {
        LOG_FAIL_FMT("Authorization header only contains one field!");
        return false;
      }
      auto auth_scheme = auth_header_value.substr(0, next_space);
      if (auth_scheme != auth::AUTH_SCHEME)
      {
        return false;
      }
      auth_header_value = auth_header_value.substr(next_space + 1);
      return true;
    }

    static bool verify_digest(
      const http::HeaderMap& headers,
      const std::vector<uint8_t>& body,
      std::string& error_reason)
    {
      // First, retrieve digest from header
      auto digest = headers.find(headers::DIGEST);
      if (digest == headers.end())
      {
        error_reason = fmt::format("Missing {} header", headers::DIGEST);
        return false;
      }

      auto equal_pos = digest->second.find("=");
      if (equal_pos == std::string::npos)
      {
        error_reason =
          fmt::format("{} header does not contain key=value", headers::DIGEST);
        return false;
      }

      auto sha_key = digest->second.substr(0, equal_pos);
      if (sha_key != auth::DIGEST_SHA256)
      {
        error_reason =
          fmt::format("Only {} digest is supported", auth::DIGEST_SHA256);
        return false;
      }

      auto raw_digest = tls::raw_from_b64(digest->second.substr(equal_pos + 1));

      // Then, hash the request body
      tls::HashBytes body_digest;
      tls::do_hash(body.data(), body.size(), body_digest, MBEDTLS_MD_SHA256);

      if (raw_digest != body_digest)
      {
        error_reason = fmt::format(
          "Request body does not match {} header, calculated body "
          "digest = {:02x}",
          headers::DIGEST,
          fmt::join(body_digest, ""));
        return false;
      }

      return true;
    }

    // Parses a delimited string with no delimiter at the end
    // (e.g. "foo,bar,baz") and returns a vector parsed string views (e.g.
    // ["foo", "bar", "baz"])
    static std::vector<std::string_view> parse_delimited_string(
      std::string_view& s, const std::string& delimiter)
    {
      std::vector<std::string_view> strings;
      bool last_string = false;

      auto next_delimiter = s.find(delimiter);
      while (next_delimiter != std::string::npos || !last_string)
      {
        auto token = s.substr(0, next_delimiter);
        if (next_delimiter == std::string::npos)
        {
          last_string = true;
        }

        strings.emplace_back(token);

        if (!last_string)
        {
          s = s.substr(next_delimiter + 1);
          next_delimiter = s.find(delimiter);
        }
      }

      return strings;
    }

    static std::optional<SignatureParams> parse_signature_params(
      std::string_view& auth_header_value)
    {
      SignatureParams sig_params = {};

      auto parsed_params =
        parse_delimited_string(auth_header_value, auth::SIGN_PARAMS_DELIMITER);

      for (auto& p : parsed_params)
      {
        auto eq_pos = p.find("=");
        if (eq_pos != std::string::npos)
        {
          auto k = p.substr(0, eq_pos);
          auto v = p.substr(eq_pos + 1);

          // Remove quotes around value, if present
          const bool begins_with_quote = v.front() == '"';
          const bool ends_with_quote = v.back() == '"';
          if (v.size() >= 2 && (begins_with_quote || ends_with_quote))
          {
            if (!(begins_with_quote && ends_with_quote))
            {
              LOG_FAIL_FMT("Unbalanced quotes in Authorization header: {}", p);
              return std::nullopt;
            }

            v = v.substr(1, v.size() - 2);
          }

          if (k == auth::SIGN_PARAMS_KEYID)
          {
            // keyId is ignored
          }
          else if (k == auth::SIGN_PARAMS_ALGORITHM)
          {
            sig_params.signature_algorithm = v;
            if (v != auth::SIGN_ALGORITHM_SHA256)
            {
              LOG_FAIL_FMT("Signature algorithm {} is not supported", v);
              return std::nullopt;
            }
          }
          else if (k == auth::SIGN_PARAMS_SIGNATURE)
          {
            sig_params.signature = v;
          }
          else if (k == auth::SIGN_PARAMS_HEADERS)
          {
            auto parsed_signed_headers =
              parse_delimited_string(v, auth::SIGN_PARAMS_HEADERS_DELIMITER);

            if (parsed_signed_headers.size() == 0)
            {
              LOG_FAIL_FMT(
                "No headers specified in {} field", auth::SIGN_PARAMS_HEADERS);
              return std::nullopt;
            }

            for (const auto& h : parsed_signed_headers)
            {
              sig_params.signed_headers.emplace_back(h);
            }
          }
        }
        else
        {
          LOG_FAIL_FMT("Authorization parameter {} does not contain \"=\"", p);
          return std::nullopt;
        }
      }

      return sig_params;
    }

    static std::optional<ccf::SignedReq> parse(
      const std::string& verb,
      const std::string_view& path,
      const std::string_view& query,
      const http::HeaderMap& headers,
      const std::vector<uint8_t>& body)
    {
      auto auth = headers.find(headers::AUTHORIZATION);
      if (auth != headers.end())
      {
        std::string_view authz_header = auth->second;

        if (!parse_auth_scheme(authz_header))
        {
          // The request does not have the correct authorization scheme
          return std::nullopt;
        }

        std::string verify_error_reason;
        if (!verify_digest(headers, body, verify_error_reason))
        {
          throw std::logic_error(fmt::format(
            "Error verifying HTTP {} header: {}",
            headers::DIGEST,
            verify_error_reason));
        }

        auto parsed_sign_params = parse_signature_params(authz_header);
        if (!parsed_sign_params.has_value())
        {
          throw std::logic_error(
            fmt::format("Error parsing {} fields", headers::AUTHORIZATION));
        }

        const auto& signed_headers = parsed_sign_params->signed_headers;
        std::vector<std::string> missing_required_headers;
        for (const auto& required_header : http::required_signature_headers)
        {
          const auto it = std::find(
            signed_headers.begin(), signed_headers.end(), required_header);
          if (it == signed_headers.end())
          {
            missing_required_headers.push_back(required_header);
          }
        }

        if (!missing_required_headers.empty())
        {
          throw std::logic_error(fmt::format(
            "HTTP signature does not cover required fields: {}",
            fmt::join(missing_required_headers, ", ")));
        }

        auto signed_raw = construct_raw_signed_string(
          verb, path, query, headers, signed_headers);
        if (!signed_raw.has_value())
        {
          throw std::logic_error(
            fmt::format("Error constructing signed string"));
        }

        auto sig_raw = tls::raw_from_b64(parsed_sign_params->signature);
        ccf::SignedReq ret = {
          sig_raw, signed_raw.value(), body, MBEDTLS_MD_SHA256};
        return ret;
      }

      // The request does not contain the Authorization header
      return std::nullopt;
    }
  };
}