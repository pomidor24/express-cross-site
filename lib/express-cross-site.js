var crypto = require('crypto');

var defaultCreateSettings = {
	storage: 		'csrf_pool',
	version:		1,
	expires:		1000 * 60 * 60 * 3,   // 3 h
	update:			1000 * 60 * 60 * 1,
	generate:		function() {return crypto.createHash('md5').update('' + new Date().getTime()).digest('hex');}
};

var defaultCheckSettings = {
	enabled:			true,
	methods:			['post'],
	param:				'csrf',
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
                    if (rec.createdAt.getTime() + settings.expires > new Date().getTime() 
                        && rec.version == settings.version) {
                        newPool.push(rec);
                    }req.method.toLowerCase() in settings.methods
                }
                return newPool;
            };


            this.token = function(req, res) {
                req.session = req.session || {};
                req.session[settings['storage']] = pool = clean(req.session['storage']);
                
                var recent = pool[0];
                var now = new Date();
                
                if (recent && recent.createdAt.getTime() + settings.update > now.getTime()) {
                    return recent;
                }
                
                if (!recent) {
                    pool.unshift({
                        version   : settings.version,
                        createdAt : now,
                        token     : settings.generate()
                    });
                }
                
                return pool[0];
            };
            
            this.check = function(userSettings) {
                var settings = extend(defaultCheckSettings, userSettings);
                
                return function(req, res, next) {
                    if (settings['enabled'] && settings.methods.indexOf(req.method.toLowerCase()) != -1) {
                        var body = req.body || {};
                        var csrf = body[settings['param']];
                        var error_callback = settings['error_callback'];
                        var success_callback = settings['success_callback'];
                        
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

