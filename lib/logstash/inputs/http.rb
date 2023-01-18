# encoding: utf-8

require "java"

require "logstash/inputs/base"
require "logstash/namespace"
require "stud/interval"
require "logstash-input-http_jars"
require "logstash/plugin_mixins/ecs_compatibility_support"

# Using this input you can receive single or multiline events over http(s).
# Applications can send a HTTP POST request with a body to the endpoint started by this
# input and Logstash will convert it into an event for subsequent processing. Users
# can pass plain text, JSON, or any formatted data and use a corresponding codec with this
# input. For Content-Type `application/json` the `json` codec is used, but for all other
# data formats, `plain` codec is used.
#
# This input can also be used to receive webhook requests to integrate with other services
# and applications. By taking advantage of the vast plugin ecosystem available in Logstash
# you can trigger actionable events right from your application.
#
# ==== Security
# This plugin supports standard HTTP basic authentication headers to identify the requester.
# You can pass in an username, password combination while sending data to this input
#
# You can also setup SSL and send data securely over https, with an option of validating 
# the client's certificate. Currently, the certificate setup is through 
# https://docs.oracle.com/cd/E19509-01/820-3503/ggfen/index.html[Java Keystore 
# format]
#
class LogStash::Inputs::Http < LogStash::Inputs::Base
  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1, :v8 => :v1)
  require "logstash/inputs/http/tls"

  java_import "io.netty.handler.codec.http.HttpUtil"
  java_import 'org.logstash.plugins.inputs.http.util.SslSimpleBuilder'

  config_name "http"

  # Codec used to decode the incoming data.
  # This codec will be used as a fall-back if the content-type
  # is not found in the "additional_codecs" hash
  default :codec, "plain"

  # The host or ip to bind
  config :host, :validate => :string, :default => "0.0.0.0"

  # The TCP port to bind to
  config :port, :validate => :number, :default => 8080

  # Username for basic authorization
  config :user, :validate => :string, :required => false

  # Password for basic authorization
  config :password, :validate => :password, :required => false

  # Events are by default sent in plain text. You can
  # enable encryption by setting `ssl` to true and configuring
  # the `ssl_certificate` and `ssl_key` options.
  config :ssl, :validate => :boolean, :default => false

  # SSL certificate to use.
  config :ssl_certificate, :validate => :path

  # SSL key to use.
  # NOTE: This key need to be in the PKCS8 format, you can convert it with https://www.openssl.org/docs/man1.1.0/apps/pkcs8.html[OpenSSL]
  # for more information.
  config :ssl_key, :validate => :path

  # SSL key passphrase to use.
  config :ssl_key_passphrase, :validate => :password

  # Validate client certificates against these authorities.
  # You can define multiple files or paths. All the certificates will
  # be read and added to the trust store. You need to configure the `ssl_verify_mode`
  # to `peer` or `force_peer` to enable the verification.
  config :ssl_certificate_authorities, :validate => :array, :default => []

  # By default the server doesn't do any client verification.
  #
  # `peer` will make the server ask the client to provide a certificate.
  # If the client provides a certificate, it will be validated.
  #
  # `force_peer` will make the server ask the client to provide a certificate.
  # If the client doesn't provide a certificate, the connection will be closed.
  #
  # This option needs to be used with `ssl_certificate_authorities` and a defined list of CAs.
  config :ssl_verify_mode, :validate => ["none", "peer", "force_peer"], :default => "none"

  # Time in milliseconds for an incomplete ssl handshake to timeout
  config :ssl_handshake_timeout, :validate => :number, :default => 10000

  # The list of ciphers suite to use, listed by priorities.
  config :ssl_cipher_suites, :validate => SslSimpleBuilder::SUPPORTED_CIPHERS.to_a,
                             :default => SslSimpleBuilder.getDefaultCiphers, :list => true

  config :ssl_supported_protocols, :validate => ['TLSv1.1', 'TLSv1.2', 'TLSv1.3'], :default => ['TLSv1.2', 'TLSv1.3'], :list => true

  # Apply specific codecs for specific content types.
  # The default codec will be applied only after this list is checked
  # and no codec for the request's content-type is found
  config :additional_codecs, :validate => :hash, :default => { "application/json" => "json" }

  # specify a custom set of response headers
  config :response_headers, :validate => :hash, :default => { 'Content-Type' => 'text/plain' }

  # target field for the client host of the http request
  config :remote_host_target_field, :validate => :string

  # target field for the client host of the http request
  config :request_headers_target_field, :validate => :string

  config :threads, :validate => :number, :required => false, :default => ::LogStash::Config::CpuCoreStrategy.maximum

  config :max_pending_requests, :validate => :number, :required => false, :default => 200

  config :max_content_length, :validate => :number, :required => false, :default => 100 * 1024 * 1024

  config :response_code, :validate => [200, 201, 202, 204], :default => 200

  # Deprecated options

  # The JKS keystore to validate the client's certificates
  config :keystore, :validate => :path
  config :keystore_password, :validate => :password

  config :verify_mode, :validate => ['none', 'peer', 'force_peer'], :default => 'none', :deprecated => "Set 'ssl_verify_mode' instead."
  config :cipher_suites, :validate => :array, :default => [], :deprecated => "Set 'ssl_cipher_suites' instead."

  # The minimum TLS version allowed for the encrypted connections. The value must be one of the following:
  # 1.0 for TLS 1.0, 1.1 for TLS 1.1, 1.2 for TLS 1.2, 1.3 for TLS 1.3
  config :tls_min_version, :validate => :number, :default => TLS.min.version, :deprecated => "Set 'ssl_supported_protocols' instead."

  # The maximum TLS version allowed for the encrypted connections. The value must be the one of the following:
  # 1.0 for TLS 1.0, 1.1 for TLS 1.1, 1.2 for TLS 1.2, 1.3 for TLS 1.3
  config :tls_max_version, :validate => :number, :default => TLS.max.version, :deprecated => "Set 'ssl_supported_protocols' instead."

  attr_reader :codecs

  public
  def register

    validate_ssl_settings!

    if @user && @password
      token = Base64.strict_encode64("#{@user}:#{@password.value}")
      @auth_token = "Basic #{token}"
    end

    @codecs = Hash.new

    @additional_codecs.each do |content_type, codec|
      @codecs[content_type] = initialize_codec(codec)
    end

    require "logstash/inputs/http/message_handler"
    message_handler = MessageHandler.new(self, @codec, @codecs, @auth_token)
    @http_server = create_http_server(message_handler)

    @remote_host_target_field ||= ecs_select[disabled: "host", v1: "[host][ip]"]
    @request_headers_target_field ||= ecs_select[disabled: "headers", v1: "[@metadata][input][http][request][headers]"]
  end # def register

  def run(queue)
    @queue = queue
    @logger.info("Starting http input listener", :address => "#{@host}:#{@port}", :ssl => "#{@ssl}")
    @http_server.run()
  end

  def stop
    @http_server.close() rescue nil
  end

  def close
    @http_server.close() rescue nil
  end

  def decode_body(headers, remote_address, body, default_codec, additional_codecs)
    content_type = headers.fetch("content_type", "")
    codec = additional_codecs.fetch(HttpUtil.getMimeType(content_type), default_codec)
    codec.decode(body) { |event| push_decoded_event(headers, remote_address, event) }
    codec.flush { |event| push_decoded_event(headers, remote_address, event) }
    true
  rescue => e
    @logger.error(
      "unable to process event.",
      :message => e.message,
      :class => e.class.name,
      :backtrace => e.backtrace
    )
    false
  end

  def push_decoded_event(headers, remote_address, event)
    add_ecs_fields(headers, event)
    event.set(@request_headers_target_field, headers)
    event.set(@remote_host_target_field, remote_address)
    decorate(event)
    @queue << event
  end

  def add_ecs_fields(headers, event)
    return if ecs_compatibility == :disabled

    http_version = headers.get("http_version")
    event.set("[http][version]", http_version) if http_version

    http_user_agent = headers.get("http_user_agent")
    event.set("[user_agent][original]", http_user_agent) if http_user_agent

    http_host = headers.get("http_host")
    domain, port = self.class.get_domain_port(http_host)
    event.set("[url][domain]", domain) if domain
    event.set("[url][port]", port) if port

    request_method = headers.get("request_method")
    event.set("[http][method]", request_method) if request_method

    request_path = headers.get("request_path")
    event.set("[url][path]", request_path) if request_path

    content_length = headers.get("content_length")
    event.set("[http][request][body][bytes]", content_length) if content_length

    content_type = headers.get("content_type")
    event.set("[http][request][mime_type]", content_type) if content_type
  end

  # match the domain and port in either IPV4, "127.0.0.1:8080", or IPV6, "[2001:db8::8a2e:370:7334]:8080", style
  # return [domain, port]
  def self.get_domain_port(http_host)
    if /^(([^:]+)|\[(.*)\])\:([\d]+)$/ =~ http_host
      ["#{$2 || $3}", $4.to_i]
    else
      [http_host, nil]
    end
  end

  def validate_ssl_settings!
    if !@ssl
      ignored_params = original_params.keys.select { |opk| opk.start_with?('ssl_', 'tls_', 'keystore', 'cipher_suites', 'verify_mode') }
      @logger.warn("SSL-related config `#{ignored_params.join('`,`')}` will not be used because `ssl` is disabled") unless ignored_params.empty?
      return # code bellow assumes `ssl => true`
    end

    # IDENTITY-CENTRIC SETTINGS
    raise_config_error! "`ssl_certificate` or `keystore` must be configured when `ssl` is enabled" unless @ssl_certificate || @keystore
    raise_config_error! "`ssl_certificate` and `keystore` cannot both be configured" if @ssl_certificate && @keystore

    raise_config_error! "`ssl_key` is required when `ssl_certificate` is present" if @ssl_certificate && !@ssl_key
    raise_config_error! "`ssl_key` is not allowed unless `ssl_certificate` is provided" if @ssl_key && !@ssl_certificate
    raise_config_error! "`ssl_key_passphrase` is not allowed unless `ssl_key` is provided" if @ssl_key_passphrase && !@ssl_key

    raise_config_error! "`keystore_password` is required when `keystore` is present" if @keystore && !@keystore_password
    raise_config_error! "`keystore_password` is not allowed unless `keystore` is present" if @keystore_password && !@keystore

    # CONFIG-CENTRIC SETTINGS
    @ssl_cipher_suites_final       = param_with_deprecated('ssl_cipher_suites', 'cipher_suites')
    @ssl_supported_protocols_final = param_with_deprecated('ssl_supported_protocols', 'tls_min_version', 'tls_max_version') do |tls_min, tls_max|
      TLS.get_supported(tls_min..tls_max).map(&:name)
    end

    # TRUST-CENTRIC SETTINGS
    @ssl_verify_mode_final = param_with_deprecated('ssl_verify_mode', 'verify_mode')

    if @ssl_verify_mode_final != "none"
      raise_config_error! "Using `ssl_verify_mode` (or `verify_mode`) set to `peer` or `force_peer` requires the configuration of trust with `ssl_certificate_authorities`" unless @ssl_certificate_authorities.any?
    elsif @ssl_certificate_authorities&.any?
      raise_config_error! "The configuration of `ssl_certificate_authorities` requires setting `ssl_verify_mode` to `peer` or `force_peer`"
    end
  end

  ##
  # Unambiguously extracts the value of a param that may be provided with one or more deprecated params
  #
  # The `transformer` block is used when one or more deprecated params are explicitly provided,
  # to transform their effective values into a single suitable value for use as-if it had been
  # provided by the preferred param.
  # It is required except in the case of simple param renames.
  #
  # @param preferred_param [String]: the preferred param name
  # @param deprecated_params [String...]: the deprecated param names
  # @yield values_from_deprecated_params [Object...]: the ordered, validated-and-transformed values of _all_
  #                                                   deprecated params, including default values.
  # @yieldreturn [Object]: a single value to use as-if it had been provided by the preferred param
  #
  # @raise `LogStash::ConfigurationError` if both preferred and deprecated params are explicitly provided
  # @return [Object]: the value of the preferred param or an equivalent derived from provided deprecated params
  #
  # @note Relies on upstream deprecation warnings, and does not emit its own
  # @note Does NOT perform validation on extracted value against the preferred_param's validator
  def param_with_deprecated(preferred_param, *deprecated_params, &transformer)
    fail ArgumentError, 'deprecated names required'  if deprecated_params.empty?
    fail ArgumentError, 'block required for multi'   if deprecated_params.size > 1 && !block_given?
    fail ArgumentError, 'transformer arity mismatch' if transformer && transformer.arity != deprecated_params.size
    deprecated_params.each do |dp|
      fail ArgumentError, "param `#{dp}` not marked deprecated" unless self.class.get_config.dig(dp, :deprecated)
    end

    deprecated_params_provided = original_params.keys.select { |k| deprecated_params.include?(k) }
    return params.fetch(preferred_param, nil) unless deprecated_params_provided.any?

    if original_params.include?(preferred_param)
      deprecated_desc = "(deprecated) `#{deprecated_params_provided.join('`,`')}`"
      raise_config_error! "Both `#{preferred_param}` and #{deprecated_desc} were set. Use only `#{preferred_param}`."
    end

    return transformer.call(params.values_at(*deprecated_params)) if transformer

    return params.fetch(deprecated_params.first)
  end

  ##
  # @param message [String]
  # @raise [LogStash::ConfigurationError]
  def raise_config_error!(message)
    raise LogStash::ConfigurationError, message
  end

  def create_http_server(message_handler)
    org.logstash.plugins.inputs.http.NettyHttpServer.new(
      @host, @port, message_handler, build_ssl_params(), @threads, @max_pending_requests, @max_content_length, @response_code)
  end

  def build_ssl_params
    return nil unless @ssl

    ssl_builder = new_ssl_builder

    ssl_builder.setCipherSuites(normalized_cipher_suites)

    if @ssl_certificate_authorities&.any?
      ssl_builder.setCertificateAuthorities(@ssl_certificate_authorities)
    end

    new_ssl_handshake_provider(ssl_builder)
  rescue java.lang.IllegalArgumentException => e
    @logger.error("SSL configuration invalid", error_details(e))
    raise LogStash::ConfigurationError, e
  end

  def new_ssl_builder
    java_import org.logstash.plugins.inputs.http.util.SslSimpleBuilder

    if @keystore
      SslSimpleBuilder::serverFromKeystore(@keystore, @keystore_password.value)
    else
      SslSimpleBuilder::serverFromCertificate(@ssl_certificate, @ssl_key, @ssl_key_passphrase&.value)
    end
  end

  def certificate_authorities_provided?
    @ssl_certificate_authorities&.any?
  end

  def require_certificate_authorities?
    @ssl_verify_mode_final != "none"
  end

  private

  def normalized_cipher_suites
    @ssl_cipher_suites_final.map(&:upcase)
  end

  def new_ssl_handshake_provider(ssl_builder)
    begin
      ssl_handler_provider = org.logstash.plugins.inputs.http.util.SslHandlerProvider.new(ssl_builder.build())
      ssl_handler_provider.setVerifyMode(@ssl_verify_mode_final.upcase)
      ssl_handler_provider.setProtocols(@ssl_supported_protocols_final)
      ssl_handler_provider.setHandshakeTimeoutMilliseconds(@ssl_handshake_timeout)
      ssl_handler_provider
    rescue java.lang.IllegalArgumentException => e
      @logger.error("SSL configuration invalid", error_details(e))
      raise LogStash::ConfigurationError, e
    rescue java.lang.Exception => e
      @logger.error("SSL configuration failed", error_details(e, true))
      raise e
    end
  end

  def error_details(e, trace = false)
    error_details = { :exception => e.class, :message => e.message }
    error_details[:backtrace] = e.backtrace if trace || @logger.debug?
    cause = e.cause
    if cause && e != cause
      error_details[:cause] = { :exception => cause.class, :message => cause.message }
      error_details[:cause][:backtrace] = cause.backtrace if trace || @logger.debug?
    end
    error_details
  end

  def initialize_codec(codec_name)
    codec_klass = LogStash::Plugin.lookup("codec", codec_name)
    if defined?(::LogStash::Plugins::Contextualizer)
      ::LogStash::Plugins::Contextualizer.initialize_plugin(execution_context, codec_klass)
    else
      codec_klass.new 
    end
  end

end # class LogStash::Inputs::Http
