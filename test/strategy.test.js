var PassportOAuth2 = require('passport-oauth2')
  , OAuth2ResourceOwnerStrategy = require('../lib/strategy')
  , AuthorizationError = PassportOAuth2.AuthorizationError
  , TokenError = PassportOAuth2.TokenError
  , InternalOAuthError = PassportOAuth2.InternalOAuthError
  , chai = require('chai');

describe('OAuth2ResourceOwnerStrategy', function () {

  describe('constructed', function () {

    describe('with normal options', function () {
      var strategy = new OAuth2ResourceOwnerStrategy({
        tokenURL: 'https://www.example.com/oauth/token',
        clientID: 'clientABCD',
        clientSecret: 'secret'
      }, function () {});

      it('should be a subclass of OAuth2Strategy', function () {
        expect(strategy).to.be.instanceof(PassportOAuth2.Strategy)
      });

      it('should be named "oauth2-resource-owner"', function () {
        expect(strategy.name).to.equal('oauth2-resource-owner');
      });
    });

    describe('without verify callback', function () {
      it('should throw', function () {
        expect(function () {
          new OAuth2ResourceOwnerStrategy({
            tokenURL: 'https://www.example.com/oauth/token',
            clientID: 'clientABCD',
            clientSecret: 'secret'
          });
        }).to.throw(TypeError, 'OAuth2ResourceOwnerStrategy requires a verify callback');
      });
    });

    describe('without a tokenURL option', function() {
      it('should throw', function() {
        expect(function() {
          new OAuth2ResourceOwnerStrategy({
            clientID: 'ABC123',
            clientSecret: 'secret'
          }, function() {});
        }).to.throw(TypeError, 'OAuth2ResourceOwnerStrategy requires a tokenURL option');
      });
    }); // without a tokenURL option

    describe('without a clientID option', function() {
      it('should throw', function() {
        expect(function() {
          new OAuth2ResourceOwnerStrategy({
            tokenURL: 'https://www.example.com/oauth2/token',
            clientSecret: 'secret'
          }, function() {});
        }).to.throw(TypeError, 'OAuth2ResourceOwnerStrategy requires a clientID option');
      });
    }); // without a clientID option

    describe('without a clientSecret option', function() {
      it('should throw', function() {
        expect(function() {
          new OAuth2ResourceOwnerStrategy({
            tokenURL: 'https://www.example.com/oauth2/token',
            clientID: 'ABC123'
          }, function() {});
        }).to.throw(TypeError, 'OAuth2ResourceOwnerStrategy requires a clientSecret option');
      });
    }); // without a clientSecret option

    describe('with only a verify callback', function() {
      it('should throw', function() {
        expect(function() {
          new OAuth2ResourceOwnerStrategy(function() {});
        }).to.throw(TypeError, 'OAuth2ResourceOwnerStrategy requires a tokenURL option');
      });
    }); // with only a verify callback
  }); //constructor

  describe('processing authorization body', function () {
    var strategy = new OAuth2ResourceOwnerStrategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret'
      },
      function(accessToken, refreshToken, profile, done) {});

    describe('without request body', function () {
      var challenge, status;
      before(function (done) {
        chai.passport.use(strategy)
        .fail(function (ch, st) {
          challenge = ch;
          status = st;
          done();
        })
        .req(function (req) {
          request = req;
        })
        .authenticate();
      });

      it('should have missing credentials message', function () {
        expect(challenge.message).to.equal('Missing credentials');
      });
      it('should store status 400', function () {
        expect(status).to.equal(400);
      });
    }); // without request body

    describe('with empty request body', function () {
      var challenge, status;
      before(function (done) {
        chai.passport.use(strategy)
        .fail(function (ch, st) {
          challenge = ch;
          status = st;
          done();
        })
        .req(function (req) {
          request = req;
          request.body = {};
        })
        .authenticate();
      });

      it('should have missing credentials message', function () {
        expect(challenge.message).to.equal('Missing credentials');
      });
      it('should store status 400', function () {
        expect(status).to.equal(400);
      });
    }); //with empty request body

    describe('with username only', function () {
      var challenge, status;
      before(function (done) {
        chai.passport.use(strategy)
        .fail(function (ch, st) {
          challenge = ch;
          status = st;
          done();
        })
        .req(function (req) {
          request = req;
          request.body = {
            username: 'Testuser'
          };
        })
        .authenticate();
      });

      it('should have missing credentials message', function () {
        expect(challenge.message).to.equal('Missing credentials');
      });
      it('should store status 400', function () {
        expect(status).to.equal(400);
      });
    }); // with username only

    describe('with password only', function () {
      var challenge, status;
      before(function (done) {
        chai.passport.use(strategy)
        .fail(function (ch, st) {
          challenge = ch;
          status = st;
          done();
        })
        .req(function (req) {
          request = req;
          request.body = {
            password: 'password'
          };
        })
        .authenticate();
      });

      it('should have missing credentials message', function () {
        expect(challenge.message).to.equal('Missing credentials');
      });
      it('should store status 400', function () {
        expect(status).to.equal(400);
      });
    }); // with password only

  }); // 'processing authorization body'

  describe('issuing authorization', function () {
    var strategy = new OAuth2ResourceOwnerStrategy({
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret'
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }

        return done(null, { id: '1234' }, { message: 'Hello' });
      });

    // overload with dummy AccessToken function
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (code !== '') { return callback(new Error('incorrect code argument')); }
      if (options.username !== 'Testuser') { return callback(new Error('incorrect username argument')); }
      if (options.password !== 'password') { return callback(new Error('incorrect password argument')); }
      if (options.grant_type !== 'password' && options.grant_type !== 'refresh_token') {
        return callback(new Error('incorrect options.grant_type argument'));
      }
      if (options.redirect_uri !== undefined) { return callback(new Error('incorrect options.redirect_uri argument')); }
      return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example', expires_in: 3600 });
    }

    describe('using valid parameters', function () {
      var user, info;
      before(function(done) {
        chai.passport.use(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
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

      it('should return a valid user object', function () {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });
      it('should return a valid info object', function () {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    }); //using valid parameters

  }); // issuing authorization

  describe('using an extra params argument in the verify function', function () {
    var strategy = new OAuth2ResourceOwnerStrategy({
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, params, profile, done) {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }

        return done(null, { id: '1234' }, params);
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
      return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example', expires_in: 3600 });
    }
    var user, info;
    before(function(done) {
      chai.passport.use(strategy)
        .success(function(u, i) {
          user = u;
          info = i;
          done();
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

    it('should store the extra params in info', function () {
      expect(info.token_type).to.equal('example');
      expect(info.expires_in).to.equal(3600);
    });
  });

  describe('using alternative field names', function () {
    var strategy = new OAuth2ResourceOwnerStrategy({
      usernameField: 'email',
      passwordField: 'pw',
      authorizationURL: 'https://www.example.com/oauth2/authorize',
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'ABC123',
      clientSecret: 'secret'
    },
    function(accessToken, refreshToken, profile, done) {
      if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
      if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
      if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
      if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }

      return done(null, { id: '1234' }, { message: 'Hello' });
    });

    // overload with dummy AccessToken function
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (code !== '') { return callback(new Error('incorrect code argument')); }
      if (options.username !== 'joe_sixpack@example.com') { return callback(new Error('incorrect username argument')); }
      if (options.password !== 'password') { return callback(new Error('incorrect password argument')); }
      if (options.grant_type !== 'password' && options.grant_type !== 'refresh_token') {
        return callback(new Error('incorrect options.grant_type argument'));
      }
      if (options.redirect_uri !== undefined) { return callback(new Error('incorrect options.redirect_uri argument')); }
      return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
    }

    var user, info;
    before(function (done) {
      chai.passport.use(strategy)
      .success(function (u, i) {
        user = u;
        info = i;
        done();
      })
      .req(function (req) {
        request = req;
        req.body = {
          email: 'joe_sixpack@example.com',
          pw: 'password'
        }
      })
      .authenticate();
    });

    it('should still be recognized as valid', function () {
      expect(user).to.be.an.Object;
    })
  });
});
