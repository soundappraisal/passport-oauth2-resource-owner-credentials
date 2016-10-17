var strategy = require('..');
var OAuth2ResourceOwnerStrategy = require('../lib/strategy');

describe('passport-oauth2-resource-owner', function() {

  it('should export Strategy constructor as module', function() {
    expect(strategy).to.be.a('function');
    expect(strategy).to.equal(strategy.Strategy);
  });

  it('should export Strategy constructor', function() {
    expect(strategy.Strategy).to.be.a('function');
  });

  it('should export an instanceof OAuth2ResourceOwnerStrategy', function () {
    expect(new strategy(
      {
        tokenURL: 'http://www.example.com/oauth/token',
        clientID: 'client',
        clientSecret: 'secret'
      },
      function () {}
    )).to.be.instanceof(OAuth2ResourceOwnerStrategy);
  });
});
