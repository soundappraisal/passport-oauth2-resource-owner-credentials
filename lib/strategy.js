var passport = require('passport-strategy')
  , PassportOAuth2 = require('passport-oauth2')
  , OAuth2 = require('oauth').OAuth2
  , OAuth2Strategy = PassportOAuth2.Strategy
  , AuthorizationError = PassportOAuth2.AuthorizationError
  , lookup = require('./utils').lookup
  , util = require('util');

/**
 * Creates an instance of `OAuth2ResourceOwnerStrategy`.
 *
 * The OAuth 2.0 authentication strategy authenticates requests using the OAuth
 * 2.0 framework.
 *
 * OAuth 2.0 provides a facility for delegated authentication, whereby users can
 * authenticate using a third-party service such as Facebook.  Delegating in
 * this manner involves a sequence of events, including redirecting the user to
 * the third-party service for authorization.  Once authorization has been
 * granted, the user is redirected back to the application and an authorization
 * code can be used to obtain credentials.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile, done) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *
 *   - `tokenURL`          URL used to obtain an access token
 *   - `clientID`          identifies client to service provider
 *   - `clientSecret`      secret used to establish ownership of the client identifer
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new OAuth2ResourceOwnerStrategy({
 *         tokenURL: 'https://www.example.com/oauth2/token',
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function OAuth2ResourceOwnerStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (!verify) { throw new TypeError('OAuth2ResourceOwnerStrategy requires a verify callback'); }
  if (!options.tokenURL) { throw new TypeError('OAuth2ResourceOwnerStrategy requires a tokenURL option'); }
  if (!options.clientID) { throw new TypeError('OAuth2ResourceOwnerStrategy requires a clientID option'); }
  if (!options.clientSecret) { throw new TypeError('OAuth2ResourceOwnerStrategy requires a clientSecret option'); }

  passport.Strategy.call(this);
  this.name = 'oauth2-resource-owner';
  this._verify = verify;

  // NOTE: The _oauth2 property is considered "protected".  Subclasses are
  //       allowed to use it when making protected resource requests to retrieve
  //       the user profile.
  this._oauth2 = new OAuth2(options.clientID,  options.clientSecret,
      '', options.authorizationURL, options.tokenURL, options.customHeaders);

  this._callbackURL = options.callbackURL;
  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || ' ';

  this._usernameField = options.usernameField || 'username';
  this._passwordField = options.passwordField || 'password';

  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
}

util.inherits(OAuth2ResourceOwnerStrategy, OAuth2Strategy);

OAuth2ResourceOwnerStrategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }
  var username = lookup(req.body, this._usernameField) || lookup(req.query, this._usernameField);
  var password = lookup(req.body, this._passwordField) || lookup(req.query, this._passwordField);

  if (!username || !password) {
    return this.fail({ message: options.badRequestMessage || 'Missing credentials' }, 400);
  }
  var params = self.tokenParams(options);
  params.username = username;
  params.password = password;
  params.grant_type = 'password';
  self._oauth2.getOAuthAccessToken('', params, function(err, accessToken, refreshToken, params) {
    if (err) {
      return self.error(self._createOAuthError('Failed to obtain access token', err));
    }
    self._loadUserProfile(accessToken, function(err, profile) {
      if (err) {
        return self.error(err);
      }
      function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }

        info = info || {};
        self.success(user, info);
      }

      try {
        if (self._passReqToCallback) {
          var arity = self._verify.length;
          if (arity == 6) {
            self._verify(req, accessToken, refreshToken, params, profile, verified);
          } else { // arity == 5
            self._verify(req, accessToken, refreshToken, profile, verified);
          }
        }
        else {
          var arity = self._verify.length;
          if (arity == 5) {
            self._verify(accessToken, refreshToken, params, profile, verified);
          } else { // arity == 4
            self._verify(accessToken, refreshToken, profile, verified);
          }
        }
      }
      catch (ex) {
        return self.error(ex);
      }
    });
  });
};

// Expose constructor.
module.exports = OAuth2ResourceOwnerStrategy;
