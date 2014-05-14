var util = require('util'), Strategy = require('passport-strategy');
var url = require("url"), request = require("request");
function CASStrategy(options, verify) {
    if (typeof options == 'function') {
	verify = options;
	options = {};
    }
    if (!verify) {
	throw new Error('cas authentication strategy requires a verify function');
    }
    
    this.ssoBase = "https://cas.iu.edu/cas";
    this.serverBaseURL = options.serverBaseURL;
    this.parsed = url.parse(this.ssoBase);
    Strategy.call(this);    
    this.name = 'cas';
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;
}

util.inherits(CASStrategy, Strategy);

CASStrategy.prototype.authenticate = function(req, options) {
    options = options || {};
    
    var ticket = req.param('ticket');
    if (!ticket) {
	var redirectURL = url.parse(this.ssoBase + '/login', true);
	var service = this.serverBaseURL + req.url;
	
	redirectURL.query.service = service;
	return this.redirect(url.format(redirectURL));
    }
    
    var resolvedURL = url.resolve(this.serverBaseURL, req.url);
    var parsedURL = url.parse(resolvedURL, true);
    delete parsedURL.query.ticket;
    delete parsedURL.search;
    var validateService = url.format(parsedURL);
    
    var self = this;
    
    var verified = function (err, user, info) {
	if (err) { return self.error(err); }
	if (!user) { return self.fail(info); }
	self.success(user, info);
    };
    var validate_url = this.ssoBase+"/validate";
    var query = {ticket:ticket, service:validateService};
    request.get({url:validate_url, qs:query}, function (err, res,  body) {
	var sections = body.split("\n");
	var validated = sections[0].trim() == "yes";
	var username = null;
	if (sections.length > 1) {
	    username = sections[1].trim();
	}
	if (validated == false) {
            return self.fail(new Error('Authentication failed'));
        } else if (validated && username) {
            if (self._passReqToCallback) {
		return self._verify(req, username, verified);
            } else {
		return self._verify(username, verified);
            }
        } else {
	    return self.fail(new Error('The response from the server was bad'));
	}
    });
};
