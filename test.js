var test = require('tape');
var pbkdf2 = require('./');
var randomBytes = require('randombytes');
var iterations = [1, 2, 10];
var algos = [
  'sha1',
  'SHA224',
  'sha224',
  'sha256',
  'sha384',
  'sha512',
  'ripemd',
  'ripemd160'
];
var lens = [8, 12, 32, 48, 200];
var passwords = ['password', 'swordfish', randomBytes(16).toString('hex')];
function testIt(iterations, algo, len, password, t) {

  t.test('iterations: ' + iterations + ' algo: ' + algo + ' len: ' + len + ' password: ' + password, function (t){
      t.plan(2);
    pbkdf2.hash(password, iterations, len, algo).then(function (hash) {
      return pbkdf2.verify(password, hash).then(function (resp) {
        t.ok(resp, 'verified correctly');
        return pbkdf2.verify(password + 'blah', hash);
      });
    }).then(function (resp) {
      t.notok(resp, 'rejects incorrect');
    });
  });
}
test('pbkdf2', function (t){
  iterations.forEach(function (iter) {
    algos.forEach(function (algo){
      lens.forEach(function (len) {
        passwords.forEach(function (password) {
          testIt(iter, algo, len, password, t);
        });
      });
    });
  });
  t.test('callbacks', function (t){
    t.plan(5);
    pbkdf2.hash('password', 500, 99, 'sha512', function (err, hash) {
      t.error(err);
      pbkdf2.verify('password', hash, function (err, resp) {
        t.error(err)
        t.ok(resp, 'verified correctly');
      });
      pbkdf2.verify('wrong', hash, function (err, resp) {
        t.error(err)
        t.notok(resp, 'rejects incorrect');
      });
    });
  });
  t.test('callbacks no algo', function (t){
    t.plan(5);
    pbkdf2.hash('no algo', 500, 99, function (err, hash) {
      t.error(err);
      pbkdf2.verify('no algo', hash, function (err, resp) {
        t.error(err)
        t.ok(resp, 'verified correctly');
      });
      pbkdf2.verify('wrong', hash, function (err, resp) {
        t.error(err)
        t.notok(resp, 'rejects incorrect');
      });
    });
  });
  t.test('promise no algo', function (t){
    t.plan(2);
    pbkdf2.hash('no algo', 500, 99).then(function (hash) {
      
      pbkdf2.verify('no algo', hash).then(function (resp) {
        t.ok(resp, 'verified correctly');
      });
      pbkdf2.verify('wrong', hash).then(function (resp) {
        t.notok(resp, 'rejects incorrect');
      });
    });
  });
  t.test('callbacks no length', function (t){
    t.plan(6);
    pbkdf2.hash('no len', 500, 'ripemd', function (err, hash) {
      t.error(err);
      t.equals(hash[1], 5, 'correct hash');
      pbkdf2.verify('no len', hash, function (err, resp) {
        t.error(err);
        t.ok(resp, 'verified correctly');
      });
      pbkdf2.verify('wrong', hash, function (err, resp) {
        t.error(err)
        t.notok(resp, 'rejects incorrect');
      });
    });
  });
  t.test('promise no length', function (t){
    t.plan(3);
    pbkdf2.hash('no len', 500, 'ripemd').then(function (hash) {
      t.equals(hash[1], 5, 'correct hash');
      pbkdf2.verify('no len', hash).then(function (resp) {
        t.ok(resp, 'verified correctly');
      });
      pbkdf2.verify('wrong', hash).then(function (resp) {
        t.notok(resp, 'rejects incorrect');
      });
    });
  });
  t.test('callbacks no algo or length', function (t){
    t.plan(5);
    pbkdf2.hash('no len or algo', 500, function (err, hash) {
      t.error(err);
      pbkdf2.verify('no len or algo', hash, function (err, resp) {
        t.error(err)
        t.ok(resp, 'verified correctly');
      });
      pbkdf2.verify('wrong', hash, function (err, resp) {
        t.error(err)
        t.notok(resp, 'rejects incorrect');
      });
    });
  });
  t.test('promise no algo or length', function (t){
    t.plan(2);
    pbkdf2.hash('no len or algo', 500).then(function (hash) {
      pbkdf2.verify('no len or algo', hash).then(function (resp) {
        t.ok(resp, 'verified correctly');
      });
      pbkdf2.verify('wrong', hash).then(function (resp) {
        t.notok(resp, 'rejects incorrect');
      });
    });
  });
});