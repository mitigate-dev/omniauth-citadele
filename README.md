# Omniauth Citadele

Omniauth strategy for using Citadele as an authentication service provider.

[![Build Status](https://travis-ci.org/mitigate-dev/omniauth-citadele.svg?branch=master)](https://travis-ci.org/mitigate-dev/omniauth-citadele)

Supported Ruby versions: 2.3+

## Related projects

- [omniauth-dnb](https://github.com/mitigate-dev/omniauth-dnb) - strategy for authenticating with DNB
- [omniauth-nordea](https://github.com/mitigate-dev/omniauth-nordea) - strategy for authenticating with Nordea
- [omniauth-seb-elink](https://github.com/mitigate-dev/omniauth-seb-elink) - strategy for authenticating with SEB
- [omniauth-swedbank](https://github.com/mitigate-dev/omniauth-swedbank) - strategy for authenticating with Swedbank

## Installation

Add these lines to your application's Gemfile (omniauth-rails_csrf_protection is required if using Rails):

    gem 'omniauth-rails_csrf_protection'
    gem 'omniauth-citadele'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install omniauth-rails_csrf_protection omniauth-citadele

## Usage

Here's a quick example, adding the middleware to a Rails app
in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :citadele,
    File.read('path/to/private.key'),
    File.read('path/to/private.crt'),
    File.read('path/to/bank.crt'),
    ENV['CITADELE_FROM'], site: ENV['CITADELE_SITE']
end
```

## Auth Hash

Here's an example Auth Hash available in `request.env['omniauth.auth']`:

```ruby
{
  provider: 'citadele',
  uid: '000000-00000',
  info: {
    full_name: 'TestDP AŠĶŪO'
  },
  extra: {
    raw_info: {
      xmldata: '<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<FIDAVISTA xmlns=\"http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-2 http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-2/fidavista.xsd\"><Header><Timestamp>20170502142652000</Timestamp><From>10000</From><Extension><Amai xmlns=\"http://online.citadele.lv/XMLSchemas/amai/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://online.citadele.lv/XMLSchemas/amai/ http://online.citadele.lv/XMLSchemas/amai/amai.xsd\"><Request>AUTHRESP</Request><RequestUID>258e4526-8129-468f-832a-493807346f96</RequestUID><Version>5.0</Version><Language>LV</Language><PersonCode>00000000000</PersonCode><Person>TestDP AŠĶŪO</Person><Code>100</Code><SignatureData><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>E3FoLc7qCoWppsPn5BPdY5GJg6CGj3BEOfoaKLsrbqI=</DigestValue></Reference></SignedInfo><SignatureValue>...</SignatureValue><KeyInfo><X509Data><X509SubjectName>...</X509SubjectName><X509Certificate>...</X509Certificate></X509Data></KeyInfo></Signature></SignatureData></Amai></Extension></Header></FIDAVISTA>'
    }
  }
}
```

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
