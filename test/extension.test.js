var PassportOAuth2 = require('passport-oauth2')
  , OAuth2ResourceOwnerStrategy = require('../lib/strategy')
  , AuthorizationError = PassportOAuth2.AuthorizationError
  , TokenError = PassportOAuth2.TokenError
  , InternalOAuthError = PassportOAuth2.InternalOAuthError
  , chai = require('chai')
  , util = require('util');

describe('OAuth2Strategy extension', function () {
  function FooResourceOwnerStrategy (options, verify) {
    OAuth2ResourceOwnerStrategy.call(this, options, verify);
  }
  util.inherits(FooResourceOwnerStrategy, OAuth2ResourceOwnerStrategy);

  var strategy = new FooResourceOwnerStrategy({
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'ABC123',
      clientSecret: 'secret',
      callbackURL: 'https://www.example.net/auth/example/callback',
    },
    function(accessToken, refreshToken, profile, done) {
      if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
      if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
      if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }

      return done(null, { id: '1234', username: profile.username}, { message: 'Hello' });
    });

  // overload with dummy AccessToken function
  strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
    if (code !== 'password') { return callback(new Error('incorrect code argument')); }
    if (options.username !== 'Testuser') { return callback(new Error('incorrect username argument')); }
    if (options.password !== 'password') { return callback(new Error('incorrect password argument')); }
    if (options.grant_type !== 'password' && options.grant_type !== 'refresh_token') {
      return callback(new Error('incorrect options.grant_type argument'));
    }
    if (options.redirect_uri !== undefined) { return callback(new Error('incorrect options.redirect_uri argument')); }
    return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
  }

  describe('that overwrites userProfile', function () {
    FooResourceOwnerStrategy.prototype.userProfile = function (accessToken, done) {
      if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') {
        console.info('access token error');
        return done(new Error('something went wrong getting the access token'));
      }
      done(null, {username: 'Joe Sixpack', location: 'Jacksonville'});
    };

    before(function (done) {
      chai.passport.use(strategy)
      .success(function(u, i) {
        user = u;
        info = i;
        done();
      })
      .error(function (err) {
        console.info(err);
      })
      .req(function(req) {
        req.query = {};
        req.body = {
          username: 'Testuser',
          password: 'password'
        }
      })
      .authenticate();
    });

    it('Should return the correct user', function () {
      expect(user.username).to.equal('Joe Sixpack');
    });
  });
});
