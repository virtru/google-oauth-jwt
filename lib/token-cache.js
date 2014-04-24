var debug = require('debug')('google-oauth-jwt');

/**
 * A cache of tokens for reusing previously requested tokens until they expire.
 *
 * Tokens are requested by calling the `authenticate` method and cached for any combination of `options.email` and
 * `options.scopes`.
 *
 * @constructor TokenCache
 */
function TokenCache() {
	// cache is just a key/value pair
	this._cache = {};
};

/**
 * Obtain an authentication token.
 *
 * First, the cache is checked for a previously obtained token.
 *
 * The key for the cache lookup is composed of:
 * - the service account email credential. Retrieved from options.email.
 * - the authentication scopes. Retrieved from options.scopes.
 * - the delegation domain. Extracted from options.delegationEmail, if present; otherwise ignored.
 *
 * If the cache does not have a token corresponding to the unique key
 * or the previously obtained token has expired, then a single request
 * will be made to retrieve a new token.
 *
 * @param options The JWT generation options.
 * @callback {Function} The callback to invoke with the resulting token.
 */
TokenCache.prototype.get = function (options, callback) {
	var credentialEmail = options.email;
  var key = credentialEmail + ':' + options.scopes.join(',');

  if(options.delegationEmail) {
    var delegationDomain = options.delegationEmail.split('@')[1];
    key += ':' + delegationDomain;
  }

	if (!this._cache[key]) {
		this._cache[key] = new TokenRequest(this.authenticate, options);
	}

  this._cache[key].get(callback);
};

/**
 * Clear all tokens previously requested by this instance.
 */
TokenCache.prototype.clear = function () {
	this._cache = {};
};

/**
 * The method to use to perform authentication and retrieving a token.
 * Used for overriding the authentication mechanism.
 *
 * @param {Object} options The JWT generation options.
 * @callback {Function} callback The callback to invoke with the resulting token.
 */
TokenCache.prototype.authenticate = require('./auth').authenticate;

/**
 * A single cacheable token request with support for concurrency.
 * @private
 * @constructor
 */
function TokenRequest(authenticate, options) {

	var self = this;
	this.status = 'expired';
	this.pendingCallbacks = [];
	
	// execute accumulated callbacks during the 'pending' state
	function fireCallbacks(err, token) {
		self.pendingCallbacks.forEach(function (callback) {
			callback(err, token);
		});
		self.pendingCallbacks = [];
	}

	TokenRequest.prototype.get = function (callback) {

		if (this.status == 'expired') {

			this.status = 'pending';
			this.pendingCallbacks.push(callback);

			authenticate(options, function (err, token) {
				if (err) {
					self.status = 'expired';
					return fireCallbacks(err, null);
				}
				self.issued = Date.now();
				self.duration = options.expiration || 60 * 60 * 1000;
				self.token = token;
				self.status = 'completed';
				return fireCallbacks(null, token);
			});

		} else if (this.status == 'pending') {
			// wait for the pending request instead of issuing a new one
			this.pendingCallbacks.push(callback);
		} else if (this.status == 'completed') {

			if (this.issued + this.duration < Date.now()) {
				this.status = 'expired';
				debug('token is expired, a new token will be requested');
				this.get(callback);
			} else {
				callback(null, this.token);
			}

		}
	};
}

/**
 * The global token cache that can be used as a default instance.
 * @type TokenCache
 */
TokenCache.global = new TokenCache();

module.exports = TokenCache;
