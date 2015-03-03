var compat = require('pbkdf2');
var Promise = require('bluebird');
var pbkdf2 = Promise.promisify(compat.pbkdf2);
var randomBytes = require('randombytes');
var algos = {
  0: 'sha1',
  1: 'sha224',
  2: 'sha256',
  3: 'sha384',
  4: 'sha512',
  5: 'ripemd160',
  'sha1': 0,
  'sha224': 1,
  'sha256': 2,
  'sha384': 3,
  'sha512': 4,
  'ripemd': 5,
  'ripemd160': 5
}
exports.hash = function (password, iterations, len, algo, callback) {
  if (typeof len !== 'number') {
    callback = algo;
    algo = len;
    len = 32;
  }
  if(typeof algo !== 'string' || !(algo in algos)) {
    callback = algo;
    algo = 'sha512';
  }
  var salt = randomBytes(16);
  var iters = new Buffer(4);
  iters.writeUInt32BE(iterations, 0);
  salt = Buffer.concat([new Buffer([len, algos[algo.toLowerCase()]]), iters, salt]);
  return pbkdf2(password, salt, iterations, len, algo).then(function (resp) {
    return Buffer.concat([salt, resp]);
  }).nodeify(callback);
};
exports.verify = function (password, hash, callback) {
  var len = hash[0];
  var algo = algos[hash[1]];
  if (hash.length !== len + 22) {
    return Promise.reject(new Error('invalid hash length'));
  }
  var iterations = hash.readUInt32BE(2);
  var salt = hash.slice(0, 22);
  hash = hash.slice(22);
  return pbkdf2(password, salt, iterations, len, algo).then(function (resp) {
    var out = 0;
    var i = -1;
    while (++i < len) {
      out |= resp[i] ^ hash[i];
    }
    return out === 0;
  }).nodeify(callback);
};