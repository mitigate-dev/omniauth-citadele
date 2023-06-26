require 'spec_helper'
require 'rack-protection'

describe OmniAuth::Strategies::Citadele do
  PRIVATE_KEY = File.read(File.join(RSpec.configuration.cert_folder, 'request.key'))
  PRIVATE_CRT = File.read(File.join(RSpec.configuration.cert_folder, 'request.crt'))
  PUBLIC_CRT = File.read(File.join(RSpec.configuration.cert_folder, 'response.crt'))

  let(:app){ Rack::Builder.new do |b|
    b.use Rack::Session::Cookie, {secret: 'abc123'}
    b.use(OmniAuth::Strategies::Citadele, PRIVATE_KEY, PRIVATE_CRT, PUBLIC_CRT, 'MY_FROM')
    b.run lambda{|env| [404, {}, ['Not Found']]}
  end.to_app }

  let(:token){ Rack::Protection::AuthenticityToken.random_token }

  let(:last_response_xmldata) { last_response.body.match(/name="xmldata" type="hidden" value="([^"]*)"/)[1] }

  context 'request phase' do
    let!(:timestamp) { '20170905175959000' }
    let!(:request_uid) { '7387bf5b-fa27-4fdd-add6-a6bfb2599f77' }

    it 'displays a single form' do
      post_to_request_phase_path
      expect(last_response.status).to eq(200)
      expect(last_response.body.scan('<form').size).to eq(1)
    end

    it 'has JavaScript code to submit the form after it is created' do
      post_to_request_phase_path
      expect(last_response.body).to be_include('</form><script type="text/javascript">document.forms[0].submit();</script>')
    end

    it 'has hidden input field xmldata with required data' do
      allow_any_instance_of(OmniAuth::Strategies::Citadele).to receive(:timestamp).and_return(timestamp)
      allow_any_instance_of(OmniAuth::Strategies::Citadele).to receive(:request_uid).and_return(request_uid)
      post_to_request_phase_path

      priv_key = OpenSSL::PKey::RSA.new(PRIVATE_KEY)
      priv_crt = OpenSSL::X509::Certificate.new(PRIVATE_CRT)
      x509_subject_name = priv_crt.subject.to_s
      x509_certificate = priv_crt.to_s.gsub(/[-]{5}(BEGIN|END).*?[-]{5}/, '').gsub('\n', '')
      doc = Nokogiri::XML(last_response_xmldata.gsub!('&quot;','"'))
      doc.remove_namespaces!
      sent_values = {
        timestamp: doc.xpath("//Timestamp").text, # Verify
        from: doc.xpath("//From").text,
        request: doc.xpath("//Request").text,
        request_uid: doc.xpath("//RequestUID").text, # Verify
        version: doc.xpath("//Version").text,
        language: doc.xpath("//Language").text,
        return_url: doc.xpath("//ReturnURL").text,
        x509_subject_name: doc.xpath("//X509SubjectName").text,
        x509_certificate: doc.xpath("//X509Certificate").text
      }

      expect(sent_values[:timestamp]).to eq timestamp
      expect(sent_values[:from]).to eq 'MY_FROM'
      expect(sent_values[:request]).to eq 'AUTHREQ'
      expect(sent_values[:request_uid]).to eq request_uid
      expect(sent_values[:version]).to eq '5.0'
      expect(sent_values[:language]).to eq 'LV'
      expect(sent_values[:return_url]).to eq 'http://example.org/auth/citadele/callback'
      expect(sent_values[:x509_subject_name]).to eq x509_subject_name
      expect(sent_values[:x509_certificate]).to eq x509_certificate
    end

    it 'xmldata has a correct signature' do
      allow_any_instance_of(OmniAuth::Strategies::Citadele).to receive(:timestamp).and_return(timestamp)
      allow_any_instance_of(OmniAuth::Strategies::Citadele).to receive(:request_uid).and_return(request_uid)
      post_to_request_phase_path

      signed_xml = <<~XML
        #{last_response_xmldata.gsub('&quot;','"')}
      XML
      pub_crt = OpenSSL::X509::Certificate.new(PRIVATE_CRT).public_key
      xmldsig = Xmldsig::SignedDocument.new(signed_xml)
      expect(xmldsig.validate(pub_crt)).to be_truthy
    end

    context 'with default options' do
      it 'has the default action tag value' do
        post_to_request_phase_path
        expect(last_response.body).to be_include("action='https://online.citadele.lv/amai/start.htm'")
      end
    end

    context 'with custom options' do
      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, {secret: 'abc123'}
        b.use(OmniAuth::Strategies::Citadele, PRIVATE_KEY, PRIVATE_CRT, PUBLIC_CRT, 'MY_FROM',
          site: 'https://test.lv/banklink')
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it 'has the custom action tag value' do
        post_to_request_phase_path
        expect(last_response.body).to be_include("action='https://test.lv/banklink'")
      end
    end

    context 'with non-existant private key file' do
      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, {secret: 'abc123'}
        b.use(OmniAuth::Strategies::Citadele, 'missing-private-key-file.pem', PRIVATE_CRT, PUBLIC_CRT, 'MY_FROM')
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it 'redirects to /auth/failure with appropriate query params' do
        post_to_request_phase_path
        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=private_key_load_err&strategy=citadele')
      end
    end

    context 'with non-existant private certificate file' do
      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, {secret: 'abc123'}
        b.use(OmniAuth::Strategies::Citadele, PRIVATE_KEY, 'missing-private-crt-file.pem', PUBLIC_CRT, 'MY_FROM')
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it 'redirects to /auth/failure with appropriate query params' do
        post_to_request_phase_path
        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=private_crt_load_err&strategy=citadele')
      end
    end

    def post_to_request_phase_path
      post(
        '/auth/citadele',
        {},
        'rack.session' => {csrf: token},
        'HTTP_X_CSRF_TOKEN' => token
      )
    end
  end

  context 'callback phase' do
    let(:auth_hash){ last_request.env['omniauth.auth'] }
    let(:response_xmldata) do
      <<~XML
      <?xml version="1.0" encoding="UTF-8"?><FIDAVISTA xmlns="http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-2 http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-2/fidavista.xsd"><Header><Timestamp>20170502115836000</Timestamp><From>10000</From><Extension><Amai xmlns="http://online.citadele.lv/XMLSchemas/amai/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://online.citadele.lv/XMLSchemas/amai/ http://online.citadele.lv/XMLSchemas/amai/amai.xsd"><Request>AUTHRESP</Request><RequestUID>9209d453-6486-407f-9a5a-522b00e59ced</RequestUID><Version>5.0</Version><Language>LV</Language><PersonCode>00000000000</PersonCode><Person>TestDP AŠĶŪO</Person><Code>100</Code><SignatureData><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>TXvVCF+1mt4MzkKoPSN4fG5/CpDXG1ME5BABCVs7Izg=</DigestValue></Reference></SignedInfo><SignatureValue>oZlsB8TLPni8w7KYtvsXUHpQySU1S1FbGdKrcKHMHOHLcBdz7bpETmLUjmrX4/JcRpZNvSHcq26xQgR+iacdaHDTxf9WzT3yFj9yLN7+XfKScc0H88dNBc3Hhv1IVCbt1GhkPJH7/w8B9yqfndS9vK2pRAyly/ZWvOvpRVuxst9ak75qFFO3k9XmTLQ2t4T8SCCW3EmgPOkV53utUtYo1SMIu2FF/CY1w5cjlZNFWRk0oCPMLAqXYMkVICuWnZJm9QTkHAblMtWneMO/uXsk6i2EgYkvaFWgtG5yiv3oqzFDaMYujgsgthPVs/DJmlWVFby+sqBtHc99VbDqbtP7+Q==</SignatureValue><KeyInfo><X509Data><X509SubjectName>/CN=DNBTEST/C=LV</X509SubjectName><X509Certificate>MIIDQjCCAiqgAwIBAgIJAJ5auG0KG8WMMA0GCSqGSIb3DQEBCwUAMB8xEDAOBgNVBAMTB0ROQlRFU1QxCzAJBgNVBAYTAkxWMB4XDTE3MDQwMzEwMDQzM1oXDTM3MDMyOTEwMDQzM1owHzEQMA4GA1UEAxMHRE5CVEVTVDELMAkGA1UEBhMCTFYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMRYJ0rKoiMbUDxiiXT0xaf8yOMu59m5DFe1A5I/1X9IZCaVEMXcd7ZJoovupOU340n2Kq5ez8zeS3mLY3WK+78MFIysc9nM7/MrTB2KYVaEnpzgN0c9MkiUq8G7LTtcLCbK/eEYmXf4vQIAXwHr6JnP7+sPd7XZhgTNbeugxyqL9Nj1zzLUBOH2v1/PzFH2KnSe/srCSb/PQs+YPpNvx8nWu4FY9ES09idp59hKnWS1M5SRWKYrc3YhLYDinV3Tjwe0uSGJIC4DNijP/QgkZ6TSIiSOuaTIQofTkFxT9r32SCTjm8oLzK6w8dvPmx2e9Q9urfD99jmiLh7N7hII7TAgMBAAGjgYAwfjAdBgNVHQ4EFgQU3vSU9SHIDGRYCE/bfS9Y27kPKuowTwYDVR0jBEgwRoAU3vSU9SHIDGRYCE/bfS9Y27kPKuqhI6QhMB8xEDAOBgNVBAMTB0ROQlRFU1QxCzAJBgNVBAYTAkxWggkAnlq4bQobxYwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEApoS7dHifbvMluHL9ypLgJ+SVr/RaAYy8WYE9lfK7CBX0cLzn4pxZm69WpWqp3qB4FxEQS2PNt6TAwexNUeWkKUrMxdnSRRw5gnMM0ELNpWd/xWvu3MHZfR0whfyQyweipttgcaCOMQoRH/DS2HeS3GcRk5ljHzRhavqqgnLY8WZ/YGtnBqFlanMzF2dfWQqld/73S0v9ygwKaC+SwVHIQ8XwgZkwxM3MxyXOuE4sx5p+KaQ7n/aRRsebEZhMUzYXd0+ekN8cNjefBmCJlkV+VxeZwo7s97A4qYMku6Ac3Zji8SUi+Qz9RD0qE8Sjrn8obEY8rDfkGoPZf+ygH4MkOA==</X509Certificate></X509Data></KeyInfo></Signature></SignatureData></Amai></Extension></Header></FIDAVISTA>
      XML
    end

    context 'with valid response' do
      before do
        post '/auth/citadele/callback', xmldata: response_xmldata
      end

      it 'sets the correct uid value in the auth hash' do
        expect(auth_hash.uid).to eq('000000-00000')
      end

      it 'sets the correct info.full_name value in the auth hash' do
        expect(auth_hash.info.full_name).to eq('TestDP AŠĶŪO')
      end
    end

    context 'with non-existant public key file' do
      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, {secret: 'abc123'}
        b.use(OmniAuth::Strategies::Citadele, PRIVATE_KEY, PRIVATE_CRT, 'missing-public-key-file.pem' )
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it 'redirects to /auth/failure with appropriate query params' do
        post '/auth/citadele/callback' # Params are not important, because we're testing public key loading
        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=public_crt_load_err&strategy=citadele')
      end
    end

    context 'with invalid response' do
      it 'detects code 200' do
        post '/auth/citadele/callback', xmldata: response_xmldata.gsub('<Code>100</Code', '<Code>200</Code')
        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=authentication_cancelled_error&strategy=citadele')
      end

      it 'detects code 300' do
        error_msg = 'system_error_300'
        xmldata = response_xmldata.gsub('<Code>100</Code', "<Code>300</Code><Message>#{error_msg}</Message>")
        post '/auth/citadele/callback', xmldata: xmldata
        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq("/auth/failure?message=#{error_msg}&strategy=citadele")
      end

      it 'detects unsupported response request' do
        xmldata = response_xmldata.gsub('<Request>AUTHRESP</Request', '<Request>AUTHRESP1</Request')
        post '/auth/citadele/callback', xmldata: xmldata
        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=unsupported_response_request&strategy=citadele')
      end

      it 'detects invalid response signature err' do
        xmldata = response_xmldata.gsub(/<SignatureValue>.{6}/, '<SignatureValue>xxyyzz')
        post '/auth/citadele/callback', xmldata: xmldata
        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=invalid_response_signature_err&strategy=citadele')
      end
    end
  end
end
