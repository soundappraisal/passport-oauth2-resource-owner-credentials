## passport-oauth2-resource-owner-credentials
---
[![Code Climate](https://codeclimate.com/github/soundappraisal/passport-oauth2-resource-owner-credentials/badges/gpa.svg)](https://codeclimate.com/github/soundappraisal/passport-oauth2-resource-owner-credentials) [![Build Status](https://travis-ci.org/soundappraisal/passport-oauth2-resource-owner-credentials.svg?branch=master)](https://travis-ci.org/soundappraisal/passport-oauth2-resource-owner-credentials) [![dependencies Status](https://david-dm.org/soundappraisal/passport-oauth2-resource-owner-credentials/status.png)](https://david-dm.org/soundappraisal/passport-oauth2-resource-owner-credentials)

A generic [Passport](http://passportjs.org) strategy to authenticate using the OAuth2 Resource Owner Credentials Flow to a specific endpoint.

**This strategy is used to get an Access Token (plus Refresh Token) from a third party endpoint (not implemented here) as a CLIENT (not a server) by using a combination of client ID, client secret, username, and password**
*(there seems to be a lot of confusion around the subject, so therefore the clarification)*

This OAuth2 flow is designed for authentication between two parties that have an implicit amount of trust. The user gives his/her credentials to the client, so from an endpoint perspective, only use this strategy if the client can be trusted (for instance, if you are creator of both the OAuth2 endpoint, and the client).

This strategy is used as initial communication between a client and an OAuth2 endpoint, for instance to log a user in, obtain his/her profile, and get a first token. After you obtain an Access Token using this strategy, created an account, etc, the Access Token can be used authenticate on subsequent requests.

For more info on OAuth strategies, take a look at the [OAuth Bible](http://oauthbible.com).

## Install
```
$ npm install passport-oauth2-resource-owner-credentials
```

## Usage
### Configure Strategy
The Resource Owner Credentials strategy authenticates users using a client ID, a client secret, a username, and a password. The strategy requires a ```verify``` callback, which accepts the retrieved credentials and the user object, and calls ```done``` providing a user.

```js
passport.use(new OAuth2ResourceOwnerStrategy({
    tokenURL: 'https://www.example.com/oauth/token',
    clientID: EXAMPLE_CLIENT_ID,
    clientSecret: EXAMPLE_CLIENT_SECRET
  },
  function (access_token, refresh_token, profile, done) {
    // your app logic here... (store tokens, create user, etc)
    User.findOne({id: profile.id}, function (err, user) {
      return cb(err, user);
    }
  }
));
```

### Authenticate Requests
To authenticate a request with username and password, use ```passport.authenticate()```, specify the ```'oauth2-resource-owner'``` strategy.

For example, as an [Express](http://expressjs.com) middleware:

```js
app.get('/auth/token',
  passport.authenticate('oauth2-resource-owner', {
    failureRedirect: '/login'
  }),
  function (req, res) {
    //successful authentication
    return res.redirect('/');
  }
}
```

## Options
View all options in the example below.
```js
passport.use(new OAuth2ResourceOwnerStrategy({
  usernameField: 'email', //define a custom username field
  passwordField: 'password', //define a custom password field
  clientID: EXAMPLE_CLIENT_ID, // ID of the client
  clientSecret: EXAMPLE_CLIENT_SECRET, // client secret
  customHeaders: { // an object of custom header values to send
    'X-Sending-Client': EXAMPLE_CLIENT_HEADER
  },
  passReqToCallback: true //passes request back to 'verify' function
}));
```

## Additional Examples
### Getting a user profile
You can override the strategy's ```userProfile``` function to GET a user profile via a custom URL, after authentication was succesful.

```js
var strategy = OAuth2ResourceOwnerStrategy;
strategy.prototype.userProfile = function (access_token, done) {
  // if your endpoint requires an 'Authorization' header instead of
  // accepting query parameters, use
  // this._oauth2.useAuthorizationHeaderforGET(true);

  // Call the GET from node-oauth to securely access our
  // account using an access token
  this._oauth2.get(EXAMPLE_PROFILE_URL, access_token,
    function (err, account) {
      if (err) {
        return done(err);
      }
      if (!account) {
        return done(new Error('Got no account from Endpoint'));
      }
      return done(null, account);
    }
  );
}

passport.use(new OAuth2ResourceOwnerStrategy({/*...*/}));
```

## License
[MIT License](https://opensource.org/licenses/MIT)

Copyright (c) 2016 Arryon Tijsma <http://www.soundappraisal.eu>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
