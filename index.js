var _ = require('lodash'),
    colors = require('colors'),
    crypto = require('crypto'),
	md5 = require('md5'),
    url = require('url'),
    util = require('util');

var headersDefaults = {
    scheme: 'x-brest-scheme',
    credential: 'x-brest-credential',
    nonce: 'x-brest-nonce',
    timestamp: 'x-brest-timestamp',
    signature: 'x-brest-signature'
};

var ONE_HOUR = 60 * 60 * 1000;

/**
 * We don't check nonce if no outer callback is used at this point
 * @param nonce
 */
function checkNonceStub(nonce, callback) {
    callback(null, true);
}

var BrestAPIkey =
{
    init: function(brest, callback){
        BrestAPIkey.settings = brest.getSetting('api_key', {enabled: true});
        if (BrestAPIkey.settings.keys && !_.isEmpty(BrestAPIkey.settings.keys)) {
            BrestAPIkey.keys = BrestAPIkey.settings.keys;
            BrestAPIkey.settings.headers = _.defaults(BrestAPIkey.settings.headers, headersDefaults);
        } else {
            console.log('Warning: no API key pairs defined. Disabling API key check'.yellow);
            BrestAPIkey.settings.enabled = false;
        }
        if (_.isFunction(BrestAPIkey.settings.checkNonce)) {
            BrestAPIkey.checkNonce = BrestAPIkey.settings.checkNonce;
        } else {
            BrestAPIkey.checkNonce = checkNonceStub;
        }
        callback();
    },

    method: {
        authenticate: function(method, req, callback){
            if (!BrestAPIkey.settings.enabled) return callback();
            //if (!req.headerss[BrestAPIkey.settings.headers_secret_key] && !req.headerss[BrestAPIkey.settings.headers_public_key]) return callback({error: "API credentials missing"});
            var headers = BrestAPIkey.settings.headers;

            if (!(req.headers[headers.scheme] || req.headers[headers.nonce] || req.headers[headers.timestamp] || req.headers[headers.credential] || req.headers[headers.signature])) {
                return callback({error: "API key headers are missing"});
            }

            BrestAPIkey.checkNonce(req.headers[headers.nonce], function(err, nonce_ok){
                if (err) return callback(err);
                if (nonce_ok) {
                    var timeDiff = Math.abs((new Date()) - req.headers[headers.timestamp]);
                    if (timeDiff > ONE_HOUR || timeDiff < 0) return callback({error: 'Your client has failed to follow Shadow Proclamation Temporal Regulations'});
                    var ln = '|'; //Line feed code
                    var url_parts = url.parse(req.url, true);

                    var queryString = [];
                    _.each(url_parts.query, function(value, key) {
                        if (_.isString(value) || _.isNumber(value) || _.isBoolean(value)) {
                            queryString.push(encodeURIComponent(key) + '=' + md5('' + value));
                        }
                    });
                    _.each(req.body, function(value, key) {
                        if (_.isString(value) || _.isNumber(value) || _.isBoolean(value)) {
                            queryString.push(encodeURIComponent(key) + '=' + md5('' + value));
                        }
                    });
                    var canonicalQuery = queryString.join('&');

                    var authenticationScheme =
                       req.headers[headers.scheme] + ln +
                       req.headers[headers.nonce] + ln +
                       req.headers[headers.timestamp] + ln +
                       req.method + ln +
                       url_parts.pathname + ln +
                       canonicalQuery + ln;

                    if (BrestAPIkey.keys[req.headers[headers.credential]]) {
                       var signature = crypto.createHmac("sha256", BrestAPIkey.keys[req.headers[headers.credential]]).update(authenticationScheme).digest("hex");
                    } else {
                       return callback({'error': 'Credentials not found'});
                    }

                    if (req.headers[headers.signature] != signature) return callback({error: 'Incorrect request signature'});
                    callback();
                } else callback({'error': 'Nonce check failed'});
            });
        }
    }
};

module.exports = BrestAPIkey;