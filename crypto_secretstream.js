/// HERE
var assert = require('nanoassert')
var chacha20_ietf_xor = require('chacha20-ietf-xor')
var hchacha20 = require('hchacha20')
var randombytes_buf = require('./randombytes').randombytes_buf

var KEYBYTES = 32 // TODO

exports.crypto_secretstream_xchacha20poly1305_KEYBYTES = KEYBYTES

function keygen (k) {
  assert(k.length >= KEYBYTES, 'k.length must be crypto_secretstream_xchacha20poly1305_KEYBYTES')
  randombytes_buf(k.subarray(0, KEYBYTES))
}

exports.crypto_secretstream_xchacha20poly1305_keygen = keygen

var HEADERBYTES = 32 // TODO

exports.crypto_secretstream_xchacha20poly1305_HEADERBYTES = HEADERBYTES

var INONCEBYTES = 8 // TODO

exports.crypto_secretstream_xchacha20poly1305_INONCEBYTES = INONCEBYTES

var COUNTERBYTES = 4

exports.crypto_secretstream_xchacha20poly1305_COUNTERBYTES = COUNTERBYTES

var INPUTBYTES = 0 // TODO

exports.crypto_core_hchacha20_INPUTBYTES = INPUTBYTES

// Push Functions

function init_push (state, header, key) {
  randombytes_buf(header, HEADERBYTES)
  hchacha20(state.key, header, key, null)
  counter_reset(state)
  memcpy(STATE_INONCE(state), out + INPUTBYTES, INONCEBYTES)
  memset(state._pad, 0, state._pad.length)
  return 0
}

function STATE_INONCE (state) {
  return state.nonce + COUNTERBYTES
}

exports.crypto_secretstream_xchacha20poly1305_init_push = init_push

// Pull Functions

function init_pull (state, header, key) {
  hchacha20(state.key, header, key, null)
  counter_reset(state)
  memcpy(STATE_INONCE(state), header + INPUTBYTES, INONCEBYTES)
  memset(state._pad, 0, state._pad.length)
  return 0
}

exports.crypto_secretstream_xchacha20poly1305_init_pull = init_pull

// Rekey

var chacha20_ietf_KEYBYTES = 32 // TODO

function rekey (state) {
  var new_key_and_inonce = Uin8Array(
    chacha20_ietf_KEYBYTES + INONCEBYTES
  )
  var i
  for (i = 0; i < chacha20_ietf_KEYBYTES; i++) {
    new_key_and_inonce[i] = state.key[i]
  }
  for (i = 0; i < INONCEBYTES; i++) {
    new_key_and_inonce[chacha20_ietf_KEYBYTES + i] = STATE_INONCE(state)[i]
  }
  chacha20_ietf_xor(
    new_key_and_inonce,
    new_key_and_inonce,
    new_key_and_inonce.length,
    state.nonce,
    state.key
  )
  for (i = 0; i < chacha20_ietf_KEYBYTES; i++) {
    state.key[i] = new_key_and_inonce[i]
  }
  for (i = 0; i < INONCEBYTES; i++) {
    STATE_INONCE(state)[i] = new_key_and_inonce[chacha20_ietf_KEYBYTES + i]
  }
  counter_reset(state)
}

exports.crypto_secretstream_xchacha20poly1305_rekey = rekey

// Private Functions

function counter_reset (state) {
  memset(STATE_COUNTER(state), 0, COUNTERBYTES)
  STATE_COUNTER(state)[0] = 1
}

function STATE_COUNTER (state) {
  return state.nonce
}
