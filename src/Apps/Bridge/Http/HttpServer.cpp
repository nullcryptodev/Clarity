// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "HttpServer.h"

#include "Http/DepositRequest.h"

#include "Common/Json.h"

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#include <chrono>
#include <iostream>
#include <string>

namespace Bridge
{
  namespace beast = boost::beast;
  namespace http = beast::http;
  namespace net = boost::asio;
  using tcp = net::ip::tcp;

  struct HttpServer::Impl
  {
    explicit Impl(net::io_context &ioc) : acceptor(ioc) {}
    tcp::acceptor acceptor;
  };

  namespace
  {
    //  A single request/response cycle. Kept out of the class
    //  body so the accept loop stays readable.
    //
    //  Returns the response to send. Never throws; a handler
    //  exception becomes a 500.
    http::response<http::string_body>
    handleOne(http::request<http::string_body> &&req,
              WatcherSession &session)
    {
      http::response<http::string_body> res{http::status::ok, req.version()};
      res.set(http::field::server, "clarity-bridge/0.1");
      res.set(http::field::content_type, "application/json");
      res.keep_alive(false);

      if (req.method() != http::verb::post)
      {
        res.result(http::status::method_not_allowed);
        res.body() = R"({"error":"method not allowed"})";
        return res;
      }

      if (req.target() != "/bridge/deposit-address")
      {
        res.result(http::status::not_found);
        res.body() = R"({"error":"no such route"})";
        return res;
      }

      Common::Json body;
      try
      {
        body = Common::Json::parse(req.body());
      }
      catch (const std::exception &e)
      {
        res.result(http::status::bad_request);
        res.body() = R"({"error":"malformed JSON"})";
        return res;
      }

      if (!body.is_object() ||
          !body.contains("destination") ||
          !body["destination"].is_string() ||
          !body.contains("authority") ||
          !body["authority"].is_string())
      {
        res.result(http::status::bad_request);
        res.body() =
            R"({"error":"required fields: destination, authority"})";
        return res;
      }

      try
      {
        const std::string dest =
            body["destination"].get<std::string>();
        const std::string auth =
            body["authority"].get<std::string>();

        const DepositRequestResult r =
            handleDepositRequest(session, dest, auth);

        Common::Json out = Common::Json::object();
        out["status"] = r.status;
        if (!r.index_hex.empty())
          out["index"] = r.index_hex;
        if (!r.address.empty())
          out["address"] = r.address;
        if (!r.confirmation_depth_hex.empty())
          out["confirmation_depth"] = r.confirmation_depth_hex;
        if (!r.registration_tx.empty())
          out["registration_tx"] = r.registration_tx;
        if (!r.error.empty())
          out["error"] = r.error;

        res.body() = out.dump();
      }
      catch (const std::exception &e)
      {
        res.result(http::status::internal_server_error);
        Common::Json err = Common::Json::object();
        err["error"] = std::string("handler exception: ") + e.what();
        res.body() = err.dump();
      }

      return res;
    }
  } // anonymous namespace

  HttpServer::HttpServer(WatcherSession &session,
                         std::string bind_address,
                         uint16_t port)
      : session_(session),
        bind_address_(std::move(bind_address)),
        requested_port_(port)
  {
  }

  HttpServer::~HttpServer()
  {
    stop();
  }

  bool HttpServer::start()
  {
    if (started_.load(std::memory_order_acquire))
      return true;

    try
    {
      net::io_context ioc(1);
      impl_ = std::make_unique<Impl>(ioc);

      const tcp::endpoint endpoint{
          net::ip::make_address(bind_address_), requested_port_};

      beast::error_code ec;
      impl_->acceptor.open(endpoint.protocol(), ec);
      if (ec)
      {
        std::cerr << "[http] open: " << ec.message() << "\n";
        impl_.reset();
        return false;
      }
      impl_->acceptor.set_option(net::socket_base::reuse_address(true), ec);
      if (ec)
      {
        std::cerr << "[http] set reuse_address: " << ec.message() << "\n";
        impl_.reset();
        return false;
      }
      impl_->acceptor.bind(endpoint, ec);
      if (ec)
      {
        std::cerr << "[http] bind " << bind_address_ << ":"
                  << requested_port_ << ": " << ec.message() << "\n";
        impl_.reset();
        return false;
      }
      impl_->acceptor.listen(net::socket_base::max_listen_connections, ec);
      if (ec)
      {
        std::cerr << "[http] listen: " << ec.message() << "\n";
        impl_.reset();
        return false;
      }

      bound_port_ = impl_->acceptor.local_endpoint().port();

      started_.store(true, std::memory_order_release);
      stop_.store(false, std::memory_order_release);
      thread_ = std::thread(&HttpServer::run, this);

      std::cerr << "[http] listening on " << bind_address_ << ":"
                << bound_port_ << "\n";
      return true;
    }
    catch (const std::exception &e)
    {
      std::cerr << "[http] start failed: " << e.what() << "\n";
      impl_.reset();
      return false;
    }
  }

  void HttpServer::stop()
  {
    if (!started_.load(std::memory_order_acquire))
      return;

    stop_.store(true, std::memory_order_release);

    if (impl_)
    {
      beast::error_code ec;
      impl_->acceptor.close(ec);
    }

    if (thread_.joinable())
      thread_.join();

    started_.store(false, std::memory_order_release);
    impl_.reset();
    bound_port_ = 0;
  }

  void HttpServer::run()
  {
    net::io_context ioc;
    tcp::acceptor &acceptor = impl_->acceptor;

    while (!stop_.load(std::memory_order_acquire))
    {
      beast::error_code ec;
      beast::tcp_stream stream(ioc);
      acceptor.accept(stream.socket(), ec);

      if (ec)
      {
        if (stop_.load(std::memory_order_acquire))
          break; // close() caused the accept to fail; expected.

        if (ec == net::error::would_block ||
            ec == net::error::try_again)
        {
          std::this_thread::sleep_for(
              std::chrono::milliseconds(50));
          continue;
        }

        std::cerr << "[http] accept: " << ec.message() << "\n";
        std::this_thread::sleep_for(
            std::chrono::milliseconds(250));
        continue;
      }

      //  Read one request with a bounded timeout, write one
      //  response, close. No keep-alive.
      try
      {
        beast::flat_buffer buffer;
        http::request<http::string_body> req;

        stream.expires_after(std::chrono::seconds(10));
        http::read(stream, buffer, req);

        http::response<http::string_body> res =
            handleOne(std::move(req), session_);

        stream.expires_after(std::chrono::seconds(10));
        http::write(stream, res);

        beast::error_code shutdown_ec;
        stream.socket().shutdown(tcp::socket::shutdown_send, shutdown_ec);
      }
      catch (const std::exception &e)
      {
        std::cerr << "[http] request handling: " << e.what() << "\n";
      }
    }
  }
} // namespace Bridge