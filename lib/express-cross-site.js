var crypto = require('crypto');

var defaultCreateSettings = {
	storage: 		'csrf_pool',
	version:		1,
	expires:		1000 * 60 * 60 * 3,   // 3 h
	update:			1000 * 60 * 60 * 1,
	max_size:		10,                   // just extra protection
	generate:		function() {return crypto.createHash('md5').update('' + new Date().getTime()).digest('hex');}
};

var defaultCheckSettings = {
    param:				function(req, res) {
        return (req.body && req.body.csrf) ? req.body.csrf : req.param('csrf', null)
    },
    enabled:            function(req, res) {
        return true;
    },
	error_callback:		function(err, req, res, next) {next(err);},
	success_callback:	function(req, res, next) {next();}
};

function extend(obj) {
	var newObj = obj;
	
    Array.prototype.slice.call(arguments).forEach(function(source) {
    	for (var prop in source) newObj[prop] = source[prop];
    });
    return newObj;
};


var CSRFAttackError = function(msg) {
	  this.name = 'CSRFAttackError';
	  this.message = msg;
	  Error.call(this, msg);
	  Error.captureStackTrace(this, arguments.callee);
}
CSRFAttackError.prototype.__proto__ = Error.prototype;

module.exports = new function() {
    this.CSRFAttackError = CSRFAttackError;
    
    this.create = function(userSettings) {

        return new function() {

            var settings = extend(defaultCreateSettings, userSettings);
            
            var clean = function(pool) {
                pool = pool || [];
                newPool = [];
                
                for (i in pool) {
                    var rec = pool[i];
                    if (rec.createdAt + settings.expires > new Date().getTime() 
                        && rec.version == settings.version) {
                        newPool.push(rec);
                    }
                }
                
                return newPool;
            };


            this.token = function(req, res) {
                req.session = req.session || {};
                req.session[settings['storage']] = pool = clean(req.session[settings['storage']]);
                
                var recent = pool[0];
                var now = new Date().getTime();
                
                if (recent && recent.createdAt + settings.update > now) {
                    return recent.token;
                } else {
                    pool.unshift({
                        version   : settings.version,
                        createdAt : now,
                        token     : settings.generate()
                    });
                }
                
                req.session[settings['storage']] = pool = pool.slice(0, settings['max_size']);
                
                return pool[0].token;
            };
            
            this.check = function(userSettings) {
                var checkSettings = extend(defaultCheckSettings, userSettings);
                
                return function(req, res, next) {
                    var enabled = checkSettings['enabled'];

                    var param = checkSettings['param']
                    var csrf = param(req, res)

                    var error_callback = checkSettings['error_callback'];
                    var success_callback = checkSettings['success_callback'];

                    if (enabled(req, res)) {
                        
                        if (!csrf) {
                            error_callback(new CSRFAttackError('CSRF token is not present'), req, res, next);
                            return;
                        }

                        var pool = req.session[settings['storage']];
                        if (!pool) {
                            error_callback(new CSRFAttackError('CSRF token is not found in session (session storage is empty)'), req, res, next);
                            return;
                        }
                        
                        req.session[settings['storage']] = pool = clean(pool);
                        for (var i in pool) {
                            if (pool[i].token = csrf) {
                                next(); return;
                            }
                        }
                        
                        error_callback(new CSRFAttackError('CSRF token '), req, res, next);
                    }
                    success_callback(req, res, next);
                };
            };
        }
    }
}

