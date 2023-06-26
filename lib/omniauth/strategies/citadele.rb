require 'omniauth'
require 'base64'
require 'xmldsig'

module OmniAuth
  module Strategies
    class Citadele
      include OmniAuth::Strategy

      PRODUCTION_ENDPOINT = 'https://online.citadele.lv/amai/start.htm'
      TEST_ENDPOINT = 'https://astra.citadele.lv/amai/start.htm'

      AUTH_REQUEST = 'AUTHREQ'
      AUTH_VERSION = '5.0'

      args [:private_key, :private_crt, :public_crt, :from]

      option :private_key, nil
      option :private_crt, nil
      option :public_crt, nil
      option :from, nil

      option :name, 'citadele'
      option :site, PRODUCTION_ENDPOINT

      def timestamp
        @timestamp ||= Time.now.strftime("%Y%m%d%H%M%S%3N")
      end

      def request_uid
        @request_uid ||= SecureRandom.uuid
      end

      def return_signed_request_xml(request_data, priv_key)
        unsigned_xml = <<~XML
        <?xml version="1.0" encoding="UTF-8"?>
        <FIDAVISTA xmlns="http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-1 http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-1/fidavista.xsd">
          <Header>
            <Timestamp>#{request_data[:timestamp]}</Timestamp>
            <From>#{request_data[:from]}</From>
            <Extension>
              <Amai xmlns="http://online.citadele.lv/XMLSchemas/amai/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://online.citadele.lv/XMLSchemas/amai/ http://online.citadele.lv/XMLSchemas/amai/amai.xsd">
                <Request>#{request_data[:request]}</Request>
                <RequestUID>#{request_data[:request_uid]}</RequestUID>
                <Version>#{request_data[:version]}</Version>
                <Language>#{request_data[:language]}</Language>
                <ReturnURL>#{request_data[:return_url]}</ReturnURL>
                <SignatureData>
                  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <SignedInfo>
                      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                      <Reference URI="">
                        <Transforms>
                          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                          <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                        </Transforms>
                        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                        <DigestValue></DigestValue>
                      </Reference>
                    </SignedInfo>
                    <SignatureValue></SignatureValue>
                    <KeyInfo>
                      <X509Data>
                        <X509SubjectName>#{request_data[:x509_subject_name]}</X509SubjectName>
                        <X509Certificate>#{request_data[:x509_certificate]}</X509Certificate>
                      </X509Data>
                    </KeyInfo>
                  </Signature>
                </SignatureData>
              </Amai>
            </Extension>
          </Header>
        </FIDAVISTA>
        XML
        unsigned_xml.gsub!('\n', '')
        unsigned_document = Xmldsig::SignedDocument.new(unsigned_xml)
        unsigned_document.sign(priv_key)
      end

      def parse_response(xml)
        doc = Nokogiri::XML(xml) do |config|
          config.strict.nonet
        end
        doc.remove_namespaces!
        {
          timestamp: doc.xpath("//Timestamp").text,
          from: doc.xpath("//From").text,
          request: doc.xpath("//Request").text,
          request_uid: doc.xpath("//RequestUID").text,
          version: doc.xpath("//Version").text,
          language: doc.xpath("//Language").text,
          person_code: doc.xpath("//PersonCode").text,
          person: doc.xpath("//Person").text,
          code: doc.xpath("//Code").text,
          message: doc.xpath("//Message").text
        }
      end

      def response_data
        @response_data ||= parse_response(request.params['xmldata'])
      end

      uid do
        response_data[:person_code].dup.insert(6, "-")
      end

      info do
        {
          full_name: response_data[:person]
        }
      end

      extra do
        { raw_info: request.params }
      end

      def callback_phase
        begin
          pub_crt = OpenSSL::X509::Certificate.new(options.public_crt).public_key
        rescue => e
          return fail!(:public_crt_load_err, e)
        end

        # Code = 100 -> success, 200, 300, 400 -> failure
        case response_data[:code]
        when '200'
          return fail!(:authentication_cancelled_error)
        when '300'
          return fail!(response_data[:message])
        end

        if response_data[:request] != 'AUTHRESP'
          return fail!(:unsupported_response_request)
        end

        xmldsig = Xmldsig::SignedDocument.new(request.params['xmldata'])
        if !xmldsig.validate(pub_crt)
          return fail!(:invalid_response_signature_err)
        end

        super
      end

      def request_phase
        begin
          priv_key = OpenSSL::PKey::RSA.new(options.private_key)
        rescue => e
          return fail!(:private_key_load_err, e)
        end

        begin
          private_crt = OpenSSL::X509::Certificate.new(options.private_crt)
        rescue => e
          return fail!(:private_crt_load_err, e)
        end

        x509_subject_name = private_crt.subject.to_s
        x509_certificate = private_crt.to_s.gsub(/[-]{5}(BEGIN|END).*?[-]{5}/, '').gsub('\n', '')

        request_data = {
          timestamp: timestamp, # '20170905175959000'
          from: options.from,
          request: AUTH_REQUEST,
          request_uid: request_uid, # '7387bf5b-fa27-4fdd-add6-a6bfb2599f77'
          version: AUTH_VERSION,
          language: 'LV',
          return_url: callback_url,
          x509_subject_name: x509_subject_name,
          x509_certificate: x509_certificate
        }
        field_value = return_signed_request_xml(request_data, priv_key)
        field_value.gsub!('"', '&quot;')

        form = OmniAuth::Form.new(title: I18n.t('omniauth.citadele.please_wait'), url: options.site)
        form.html "<input id=\"xmldata\" name=\"xmldata\" type=\"hidden\" value=\"#{field_value}\" />"
        form.button I18n.t('omniauth.citadele.click_here_if_not_redirected')

        csrf = request.env['rack.session']['csrf']
        unless csrf.nil?
          form.html "<input type=\"hidden\" name=\"authenticity_token\" value=\"#{escape(csrf)}\" />"
        end

        form.instance_variable_set('@html',
          form.to_html.gsub('</form>', '</form><script type="text/javascript">document.forms[0].submit();</script>'))
        form.to_response
      end

      private

      def escape(html_attribute_value)
         CGI.escapeHTML(html_attribute_value) unless html_attribute_value.nil?
      end
    end
  end
end
