
/**
* Client side JavaScript code for the ESP8266 based
* power meter M-Bus to mqtt gateway v2.0
* 
* PreyMa (Matthias Preymann) 2023
* 
* Most of the code is a vanilla JS implementation of
* the Chacha20 Poly1305 cipher with HKDF key derivation
* that is provided by the ESP8266 Arduino project. There
* it is implemented by the BearSSL cryptography library,
* but as JS has no access to the browser's crypto module
* when executed in an insecure HTTP context.
* 
* The code below consists of stuff taken from other
* people that was adapted and modernized, and stuff
* written by myself. Each code section is marked,
* and credits go to:
* 
* - Steven Barnett
* - Paul Rumkin
* - The wikipedia community
**/

(function() {

	// Common long names get redefined for better minification
	const _Uint8Array = Uint8Array;
	const _Uint16Array= Uint16Array;
	const _Uint32Array = Uint32Array;
	const _sessionStorage= sessionStorage;
	const _document= document;
  const _window= window;

	const hmacDigest= (function() {
    
		/**
    * A simple, open-source, HMAC-SHA256 implementation in pure JavaScript.
    * Designed for efficient minification.
    * by Steven Barnett (https://github.com/stevendesu)
    *
    * https://gist.github.com/stevendesu/2d52f7b5e1f1184af3b667c0b5e054b8
    * 
    * Changes: A bit of unused code was removed.
    *
    * License: Feel free to use it however you'd like 😄 As the gist title
    * indicates, this is "a simple open source implementation". Feel free
    * to choose whatever license you find most permissible, but I offer no
    * warranty for the code. It's 100% free to do with as you please.
    **/


		// To ensure cross-browser support even without a proper SubtleCrypto
		// impelmentation (or without access to the impelmentation, as is the case with
		// Chrome loaded over HTTP instead of HTTPS), this library can create SHA-256
		// HMAC signatures using nothing but raw JavaScript

		/* eslint-disable no-magic-numbers, id-length, no-param-reassign, new-cap */

		// By giving internal functions names that we can mangle, future calls to
		// them are reduced to a single byte (minor space savings in minified file)
		// Some are moved out of the module iife
		const pow = Math.pow;

		// Will be initialized below
		// Using a _Uint32Array instead of a simple array makes the minified code
		// a bit bigger (we lose our `unshift()` hack), but comes with huge
		// performance gains
		const DEFAULT_STATE = new _Uint32Array(8);
		const ROUND_CONSTANTS = [];

		// Reusable object for expanded message
		// Using a _Uint32Array instead of a simple array makes the minified code
		// 7 bytes larger, but comes with huge performance gains
		const M = new _Uint32Array(64);

		// After minification the code to compute the default state and round
		// constants is smaller than the output. More importantly, this serves as a
		// good educational aide for anyone wondering where the magic numbers come
		// from. No magic numbers FTW!
		function getFractionalBits(n)
		{
			return ((n - (n | 0)) * pow(2, 32)) | 0;
		}

		var n = 2, nPrime = 0;
		while (nPrime < 64)
		{
			// isPrime() was in-lined from its original function form to save
			// a few bytes
			var isPrime = true;
			// Math.sqrt() was replaced with pow(n, 1/2) to save a few bytes
			// var sqrtN = pow(n, 1 / 2);
			// So technically to determine if a number is prime you only need to
			// check numbers up to the square root. However this function only runs
			// once and we're only computing the first 64 primes (up to 311), so on
			// any modern CPU this whole function runs in a couple milliseconds.
			// By going to n / 2 instead of sqrt(n) we net 8 byte savings and no
			// scaling performance cost
			for (var factor = 2; factor <= n / 2; factor++)
			{
				if (n % factor === 0)
				{
					isPrime = false;
				}
			}
			if (isPrime)
			{
				if (nPrime < 8)
				{
					DEFAULT_STATE[nPrime] = getFractionalBits(pow(n, 1 / 2));
				}
				ROUND_CONSTANTS[nPrime] = getFractionalBits(pow(n, 1 / 3));

				nPrime++;
			}

			n++;
		}

		// For cross-platform support we need to ensure that all 32-bit words are
		// in the same endianness. A UTF-8 TextEncoder will return BigEndian data,
		// so upon reading or writing to our ArrayBuffer we'll only swap the bytes
		// if our system is LittleEndian (which is about 99% of CPUs)
		const LittleEndian = !!new _Uint8Array(new _Uint32Array([1]).buffer)[0];

		function convertEndian(word)
		{
			if (LittleEndian)
			{
				return (
					// byte 1 -> byte 4
					(word >>> 24) |
					// byte 2 -> byte 3
					(((word >>> 16) & 0xff) << 8) |
					// byte 3 -> byte 2
					((word & 0xff00) << 8) |
					// byte 4 -> byte 1
					(word << 24)
				);
			}
			else
			{
				return word;
			}
		}

		function rightRotate(word, bits)
		{
			return (word >>> bits) | (word << (32 - bits));
		}

		function sha256(data)
		{
			// Copy default state
			var STATE = DEFAULT_STATE.slice();

			// Caching this reduces occurrences of ".length" in minified JavaScript
			// 3 more byte savings! :D
			var legth = data.length;

			// Pad data
			var bitLength = legth * 8;
			var newBitLength = (512 - ((bitLength + 64) % 512) - 1) + bitLength + 65;

			// "bytes" and "words" are stored BigEndian
			var bytes = new _Uint8Array(newBitLength / 8);
			var words = new _Uint32Array(bytes.buffer);

			bytes.set(data, 0);
			// Append a 1
			bytes[legth] = 0b10000000;
			// Store length in BigEndian
			words[words.length - 1] = convertEndian(bitLength);

			// Loop iterator (avoid two instances of "var") -- saves 2 bytes
			var round;

			// Process blocks (512 bits / 64 bytes / 16 words at a time)
			for (var block = 0; block < newBitLength / 32; block += 16)
			{
				var workingState = STATE.slice();

				// Rounds
				for (round = 0; round < 64; round++)
				{
					var MRound;
					// Expand message
					if (round < 16)
					{
						// Convert to platform Endianness for later math
						MRound = convertEndian(words[block + round]);
					}
					else
					{
						var gamma0x = M[round - 15];
						var gamma1x = M[round - 2];
						MRound =
							M[round - 7] + M[round - 16] + (
								rightRotate(gamma0x, 7) ^
								rightRotate(gamma0x, 18) ^
								(gamma0x >>> 3)
							) + (
								rightRotate(gamma1x, 17) ^
								rightRotate(gamma1x, 19) ^
								(gamma1x >>> 10)
							)
						;
					}

					// M array matches platform endianness
					M[round] = MRound |= 0;

					// Computation
					var t1 =
						(
							rightRotate(workingState[4], 6) ^
							rightRotate(workingState[4], 11) ^
							rightRotate(workingState[4], 25)
						) +
						(
							(workingState[4] & workingState[5]) ^
							(~workingState[4] & workingState[6])
						) + workingState[7] + MRound + ROUND_CONSTANTS[round]
					;
					var t2 =
						(
							rightRotate(workingState[0], 2) ^
							rightRotate(workingState[0], 13) ^
							rightRotate(workingState[0], 22)
						) +
						(
							(workingState[0] & workingState[1]) ^
							(workingState[2] & (workingState[0] ^
							workingState[1]))
						)
					;

					for (var i = 7; i > 0; i--)
					{
						workingState[i] = workingState[i - 1];
					}
					workingState[0] = (t1 + t2) | 0;
					workingState[4] = (workingState[4] + t1) | 0;
				}

				// Update state
				for (round = 0; round < 8; round++)
				{
					STATE[round] = (STATE[round] + workingState[round]) | 0;
				}
			}

			// Finally the state needs to be converted to BigEndian for output
			// And we want to return a _Uint8Array, not a _Uint32Array
			return new _Uint8Array(new _Uint32Array(
				STATE.map(function(val) { return convertEndian(val); })
			).buffer);
		}

		function hmac(key, data)
		{
			if (key.length > 64)
				key = sha256(key);

			if (key.length < 64)
			{
				const tmp = new _Uint8Array(64);
				tmp.set(key, 0);
				key = tmp;
			}

			// Generate inner and outer keys
			var innerKey = new _Uint8Array(64);
			var outerKey = new _Uint8Array(64);
			for (var i = 0; i < 64; i++)
			{
				innerKey[i] = 0x36 ^ key[i];
				outerKey[i] = 0x5c ^ key[i];
			}

			// Append the innerKey
			var msg = new _Uint8Array(data.length + 64);
			msg.set(innerKey, 0);
			msg.set(data, 64);

			// Has the previous message and append the outerKey
			var result = new _Uint8Array(64 + 32);
			result.set(outerKey, 0);
			result.set(sha256(msg), 64);

			// Hash the previous message
			return sha256(result);
		}

		// Convert a string to a _Uint8Array, SHA-256 it, and convert back to string
		const encoder = new TextEncoder("utf-8");

		function sign(inputKey, inputData)
		{
			const key = typeof inputKey === "string" ? encoder.encode(inputKey) : inputKey;
			const data = typeof inputData === "string" ? encoder.encode(inputData) : inputData;
			return hmac(key, data);
		}
		
		return sign;
	})();

	const hkdfDerive= (function() {
    
		/**
    * Pure JS implementation of the simple HKDF key derivation algorithm using
    * SHA-256 hashing. This follows the Python code example shown on wikipedia:
    * by the wikipedia community, ported to JS by PreyMa
    *
    * https://en.wikipedia.org/wiki/HKDF
    *
    * License: Creative Commons Attribution-ShareAlike License 4.0
    **/
    
    
		const HASH_LENGTH = 32

		function hkdfExtract(salt, ikm) {
			if(!salt || salt.length == 0) {
				salt = new _Uint8Array(HASH_LENGTH)
			}
			return hmacDigest(salt, ikm)
		}

		function hkdfExpand(prk, info, length) {
			const tbuf = new _Uint8Array(HASH_LENGTH+ info.length+ 1);	
			const iterations= Math.ceil(length / HASH_LENGTH);
			let okm = new _Uint8Array(iterations* HASH_LENGTH);
			
			let mac= null;
			for(let i= 0; i!== iterations; i++) {
				
				let t= null;
				if( i === 0 ) {
					tbuf.set(info, 0);
					tbuf[info.length]= i+ 1;
					t = tbuf.subarray(0, info.length+ 1);
				} else if(i === 1) {
					tbuf.set(mac, 0)
					tbuf.set(info, mac.length);
					tbuf[mac.length+ info.length]= i+ 1;
					t = tbuf;
				} else {
					tbuf.set(mac, 0);
					tbuf[mac.length+ info.length]= i+ 1;
					t = tbuf;
				}
				
				mac = hmacDigest(prk, t)
				okm.set(mac, i* HASH_LENGTH);
			}
			
			return okm.subarray(0, length);
		}

		function hkdf(salt, ikm, info, length) {
			prk = hkdfExtract(salt, ikm)
			return hkdfExpand(prk, info, length)
		}
		
		return hkdf;
	})();
	
	const {
		aeadEncrypt,
		aeadDecrypt
	}= (function() {
    
		/**
    * Chacha20-Poly1305.js
    * by Paul Rumkin (https://github.com/rumkin)
    *
    * https://gist.github.com/rumkin/e852eb12fe11281a5738c0a8abaf5e1a
    * 
    * Changes: All files were concatenated and constructor functions
    * were replaced with ESM classes.
    *
    * License: Public domain
    **/


		/* chacha20 - 256 bits */

		// Written in 2014 by Devi Mandiri. Public domain.
		//
		// Implementation derived from chacha-ref.c version 20080118
		// See for details: http://cr.yp.to/chacha/chacha-20080128.pdf

		function U8TO32_LE(x, i) {
		  return x[i] | (x[i+1]<<8) | (x[i+2]<<16) | (x[i+3]<<24);
		}

		function U32TO8_LE(x, i, u) {
		  x[i]   = u; u >>>= 8;
		  x[i+1] = u; u >>>= 8;
		  x[i+2] = u; u >>>= 8;
		  x[i+3] = u;
		}

		function ROTATE(v, c) {
		  return (v << c) | (v >>> (32 - c));
		}

		class Chacha20 {
			constructor(key, nonce, counter) {
			  this.input = new _Uint32Array(16);

			  // https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01#section-2.3
			  this.input[0] = 1634760805;
			  this.input[1] =  857760878;
			  this.input[2] = 2036477234;
			  this.input[3] = 1797285236;
			  this.input[4] = U8TO32_LE(key, 0);
			  this.input[5] = U8TO32_LE(key, 4);
			  this.input[6] = U8TO32_LE(key, 8);
			  this.input[7] = U8TO32_LE(key, 12);
			  this.input[8] = U8TO32_LE(key, 16);
			  this.input[9] = U8TO32_LE(key, 20);
			  this.input[10] = U8TO32_LE(key, 24);
			  this.input[11] = U8TO32_LE(key, 28);
			  this.input[12] = counter;
			  this.input[13] = U8TO32_LE(nonce, 0);
			  this.input[14] = U8TO32_LE(nonce, 4);
			  this.input[15] = U8TO32_LE(nonce, 8);
			}

			quarterRound(x, a, b, c, d) {
			  x[a] += x[b]; x[d] = ROTATE(x[d] ^ x[a], 16);
			  x[c] += x[d]; x[b] = ROTATE(x[b] ^ x[c], 12);
			  x[a] += x[b]; x[d] = ROTATE(x[d] ^ x[a],  8);
			  x[c] += x[d]; x[b] = ROTATE(x[b] ^ x[c],  7);
			}

			encrypt(dst, src, len) {
			  var x = new _Uint32Array(16);
			  var output = new _Uint8Array(64);
			  var i, dpos = 0, spos = 0;

			  while (len > 0 ) {
				for (i = 16; i--;) x[i] = this.input[i];
				for (i = 20; i > 0; i -= 2) {
				  this.quarterRound(x, 0, 4, 8,12);
				  this.quarterRound(x, 1, 5, 9,13);
				  this.quarterRound(x, 2, 6,10,14);
				  this.quarterRound(x, 3, 7,11,15);
				  this.quarterRound(x, 0, 5,10,15);
				  this.quarterRound(x, 1, 6,11,12);
				  this.quarterRound(x, 2, 7, 8,13);
				  this.quarterRound(x, 3, 4, 9,14);
				}
				for (i = 16; i--;) x[i] += this.input[i];
				for (i = 16; i--;) U32TO8_LE(output, 4*i, x[i]);

				this.input[12] += 1;
				if (!this.input[12]) {
				  this.input[13] += 1;
				}
				if (len <= 64) {
				  for (i = len; i--;) {
					dst[i+dpos] = src[i+spos] ^ output[i];
				  }
				  return;
				}
				for (i = 64; i--;) {
				  dst[i+dpos] = src[i+spos] ^ output[i];
				}
				len -= 64;
				spos += 64;
				dpos += 64;
			  }
			}

			keystream(dst, len) {
			  for (var i = 0; i < len; ++i) dst[i] = 0;
			  this.encrypt(dst, dst, len);
			}
		}



		/* poly1305 */
		 
		// Written in 2014 by Devi Mandiri. Public domain.
		//
		// Implementation derived from poly1305-donna-16.h
		// See for details: https://github.com/floodyberry/poly1305-donna
		
		const Poly1305KeySize = 32;
		const Poly1305TagSize = 16;

		function U8TO16_LE(p, pos) {
		  return (p[pos] & 0xff) | ((p[pos+1] & 0xff) << 8);
		}
		 
		function U16TO8_LE(p, pos, v) {
		  p[pos]   = v;
		  p[pos+1] = v >>> 8;
		}

		class Poly1305 {
			constructor(key) {
			  this.buffer = new _Uint8Array(16);
			  this.leftover = 0;
			  this.r = new _Uint16Array(10);
			  this.h = new _Uint16Array(10);
			  this.pad = new _Uint16Array(8);
			  this.finished = 0;

			  var t = new _Uint16Array(8), i;
			 
			  for (i = 8; i--;) t[i] = U8TO16_LE(key, i*2);
			 
			  this.r[0] =   t[0]                         & 0x1fff;
			  this.r[1] = ((t[0] >>> 13) | (t[1] <<  3)) & 0x1fff;
			  this.r[2] = ((t[1] >>> 10) | (t[2] <<  6)) & 0x1f03;
			  this.r[3] = ((t[2] >>>  7) | (t[3] <<  9)) & 0x1fff;
			  this.r[4] = ((t[3] >>>  4) | (t[4] << 12)) & 0x00ff;
			  this.r[5] =  (t[4] >>>  1)                 & 0x1ffe;
			  this.r[6] = ((t[4] >>> 14) | (t[5] <<  2)) & 0x1fff;
			  this.r[7] = ((t[5] >>> 11) | (t[6] <<  5)) & 0x1f81;
			  this.r[8] = ((t[6] >>>  8) | (t[7] <<  8)) & 0x1fff;
			  this.r[9] =  (t[7] >>>  5)                 & 0x007f;
			 
			  for (i = 8; i--;) {
				this.h[i]   = 0;
				this.pad[i] = U8TO16_LE(key, 16+(2*i));
			  }
			  this.h[8] = 0;
			  this.h[9] = 0;
			  this.leftover = 0;
			  this.finished = 0;  
			}

			blocks(m, mpos, bytes) {
			  var hibit = this.finished ? 0 : (1 << 11);
			  var t = new _Uint16Array(8),
				  d = new _Uint32Array(10),
				  c = 0, i = 0, j = 0;
			 
			  while (bytes >= 16) {
				for (i = 8; i--;) t[i] = U8TO16_LE(m, i*2+mpos);
			 
				this.h[0] +=   t[0]                         & 0x1fff;
				this.h[1] += ((t[0] >>> 13) | (t[1] <<  3)) & 0x1fff;
				this.h[2] += ((t[1] >>> 10) | (t[2] <<  6)) & 0x1fff;
				this.h[3] += ((t[2] >>>  7) | (t[3] <<  9)) & 0x1fff;
				this.h[4] += ((t[3] >>>  4) | (t[4] << 12)) & 0x1fff;
				this.h[5] +=  (t[4] >>>  1)                 & 0x1fff;
				this.h[6] += ((t[4] >>> 14) | (t[5] <<  2)) & 0x1fff;
				this.h[7] += ((t[5] >>> 11) | (t[6] <<  5)) & 0x1fff;
				this.h[8] += ((t[6] >>>  8) | (t[7] <<  8)) & 0x1fff;
				this.h[9] +=  (t[7] >>>  5)                 | hibit;
			 
				for (i = 0, c = 0; i < 10; i++) {
				  d[i] = c;
				  for (j = 0; j < 10; j++) {
					d[i] += (this.h[j] & 0xffffffff) * ((j <= i) ? this.r[i-j] : (5 * this.r[i+10-j]));
					if (j === 4) {
					  c = (d[i] >>> 13);
					  d[i] &= 0x1fff;
					}
				  }
				  c += (d[i] >>> 13);
				  d[i] &= 0x1fff;
				}
				c = ((c << 2) + c);
				c += d[0];
				d[0] = ((c & 0xffff) & 0x1fff);
				c = (c >>> 13);
				d[1] += c;
			 
				for (i = 10; i--;) this.h[i] = d[i];
			 
				mpos += 16;
				bytes -= 16;
			  }
			}

			update(m, bytes) {
			  var want = 0, i = 0, mpos = 0;
			 
			  if (this.leftover) {
				want = 16 - this.leftover;
				if (want > bytes)
				  want = bytes;
				for (i = want; i--;) {
				  this.buffer[this.leftover+i] = m[i+mpos];
				}
				bytes -= want;
				mpos += want;
				this.leftover += want;
				if (this.leftover < 16)
				  return;
				this.blocks(this.buffer, 0, 16);
				this.leftover = 0;    
			  }
			 
			  if (bytes >= 16) {
				want = (bytes & ~(16 - 1));
				this.blocks(m, mpos, want);
				mpos += want;
				bytes -= want;
			  }
			 
			  if (bytes) {
				for (i = bytes; i--;) {
				  this.buffer[this.leftover+i] = m[i+mpos];
				}
				this.leftover += bytes;
			  }
			}
			 
			finish() {
			  var mac = new _Uint8Array(16),
				  g = new _Uint16Array(10),
				  c = 0, mask = 0, f = 0, i = 0;
			 
			  if (this.leftover) {
				i = this.leftover;
				this.buffer[i++] = 1;
				for (; i < 16; i++) {
				  this.buffer[i] = 0;
				}
				this.finished = 1;
				this.blocks(this.buffer, 0, 16);
			  }
			 
			  c = this.h[1] >>> 13;
			  this.h[1] &= 0x1fff;
			  for (i = 2; i < 10; i++) {
				this.h[i] += c;
				c = this.h[i] >>> 13;
				this.h[i] &= 0x1fff;
			  }
			  this.h[0] += (c * 5);
			  c = this.h[0] >>> 13;
			  this.h[0] &= 0x1fff;
			  this.h[1] += c;
			  c = this.h[1] >>> 13;
			  this.h[1] &= 0x1fff;
			  this.h[2] += c;
			 
			  g[0] = this.h[0] + 5;
			  c = g[0] >>> 13;
			  g[0] &= 0x1fff;
			  for (i = 1; i < 10; i++) {
				g[i] = this.h[i] + c;
				c = g[i] >>> 13;
				g[i] &= 0x1fff;
			  }
			  g[9] -= (1 << 13);
			 
			  mask = (g[9] >>> 15) - 1;
			  for (i = 10; i--;) g[i] &= mask;
			  mask = ~mask;
			  for (i = 10; i--;) {
				this.h[i] = (this.h[i] & mask) | g[i];
			  }
			 
			  this.h[0] = (this.h[0]      ) | (this.h[1] << 13);
			  this.h[1] = (this.h[1] >>  3) | (this.h[2] << 10);
			  this.h[2] = (this.h[2] >>  6) | (this.h[3] <<  7);
			  this.h[3] = (this.h[3] >>  9) | (this.h[4] <<  4);
			  this.h[4] = (this.h[4] >> 12) | (this.h[5] <<  1) | (this.h[6] << 14);
			  this.h[5] = (this.h[6] >>  2) | (this.h[7] << 11);
			  this.h[6] = (this.h[7] >>  5) | (this.h[8] <<  8);
			  this.h[7] = (this.h[8] >>  8) | (this.h[9] <<  5);
			 
			  f = (this.h[0] & 0xffffffff) + this.pad[0];
			  this.h[0] = f;
			  for (i = 1; i < 8; i++) {
				f = (this.h[i] & 0xffffffff) + this.pad[i] + (f >>> 16);
				this.h[i] = f;
			  }
			 
			  for (i = 8; i--;) {
				U16TO8_LE(mac, i*2, this.h[i]);
				this.pad[i] = 0;
			  }
			  for (i = 10; i--;) {
				this.h[i] = 0;
				this.r[i] = 0;
			  }

			  return mac;
			}
		}

		function poly1305_auth(m, bytes, key) {
		  var ctx = new Poly1305(key);
		  ctx.update(m, bytes);
		  return ctx.finish();
		}

		function poly1305_verify(mac1, mac2) {
		  var dif = 0;
		  for (var i = 0; i < 16; i++) {
			dif |= (mac1[i] ^ mac2[i]);
		  }
		  dif = (dif - 1) >>> 31;
		  return (dif & 1);
		}

		/* chacha20poly1305 AEAD */

		// Written in 2014 by Devi Mandiri. Public domain.

		function store64(dst, num) {
		  var hi = 0, lo = num >>> 0;
		  if ((+(Math.abs(num))) >= 1) {
			if (num > 0) {
			  hi = ((Math.min((+(Math.floor(num/4294967296))), 4294967295))|0) >>> 0;
			} else {
			  hi = (~~((+(Math.ceil((num - +(((~~(num)))>>>0))/4294967296))))) >>> 0;
			}
		  }
		  dst.push(lo & 0xff); lo >>>= 8;
		  dst.push(lo & 0xff); lo >>>= 8;
		  dst.push(lo & 0xff); lo >>>= 8;
		  dst.push(lo & 0xff);
		  dst.push(hi & 0xff); hi >>>= 8;
		  dst.push(hi & 0xff); hi >>>= 8;
		  dst.push(hi & 0xff); hi >>>= 8;
		  dst.push(hi & 0xff);
		}

		function aead_mac(polykey, data, ciphertext) {
		  var dlen = data.length,
			  clen = ciphertext.length,
			  dpad = dlen % 16,
			  cpad = clen % 16,
			  m = [], i;

		  for (i = 0; i < dlen; i++) m.push(data[i]);

		  if (dpad !== 0) {
			for (i = (16 - dpad); i--;) m.push(0);
		  }

		  for (i = 0; i < clen; i++) m.push(ciphertext[i]);

		  if (cpad !== 0) {
			for (i = (16 - cpad); i--;) m.push(0);
		  }

		  store64(m, dlen);
		  store64(m, clen);

		  return poly1305_auth(m, m.length, polykey);
		}

		function aead_encrypt(key, nonce, plaintext, data) {
		  var plen = plaintext.length,
			  buf = new _Uint8Array(plen),
			  cipherText = new _Uint8Array(plen),
			  polykey = new _Uint8Array(64),
			  ctx = new Chacha20(key, nonce, 0);

		  ctx.keystream(polykey, 64);

		  ctx.keystream(buf, plen);

		  for (var i = 0; i < plen; i++) {
			cipherText[i] = buf[i] ^ plaintext[i];
		  }

		  return { cipherText, tag: aead_mac(polykey, data, cipherText) };
		}

		function aead_decrypt(key, nonce, ciphertext, data, mac) {
		  var plen = ciphertext.length,
			  buf = new _Uint8Array(plen),
			  plaintext = new _Uint8Array(plen),
			  polykey = new _Uint8Array(64),
			  ctx = new Chacha20(key, nonce, 0);

		  ctx.keystream(polykey, 64);

		  var tag = aead_mac(polykey, data, ciphertext);

		  if (poly1305_verify(tag, mac) !== 1) {
			  return null;
		  }

		  ctx.keystream(buf, plen);

		  for (var i = 0; i < plen; i++) {
			plaintext[i] = buf[i] ^ ciphertext[i];
		  }

		  return plaintext;
		}
		
		return {
			aeadEncrypt: aead_encrypt,
			aeadDecrypt: aead_decrypt
		};
	})();
	
	(function() {
		
    /**
    * Front-end code for the UI
    **/
    
		let formNonceString= null;
		
		function fail(msg= "An error occurred") {
			alert(msg);
			//_window.location.href= "/";
		}
    
		function getOrPromptForKey() {
			let keyString= _sessionStorage.getItem('key');
			if( !keyString ) {
				const hexString= prompt('Enter your passcode');
        if( !hexString ) {
          throw Error('No key entered');
        }
        keyString= bufferToBase64String(hexStringToBuffer(hexString));
				_sessionStorage.setItem('key', keyString);
			}
			return keyString;
		}
    
    function clearKey() {
      _sessionStorage.removeItem('key');
    }
		
    function hexStringToBuffer(dataString) {
      const buffer= new Uint8Array(Math.floor(dataString.length / 2) );
      for( let i= 0; i< dataString.length; i+= 2) {
        const digits= dataString.substr(i, 2);
        const num= parseInt(digits, 16);
        if( isNaN(num) ) {
          fail(`Bad hex character '${digits}'`);
          return;
        }
        buffer[i/2]= num;
      }
      return buffer;
    }
		
		function base64StringToBuffer(dataString) {
			return _Uint8Array.from(atob(dataString), c => c.charCodeAt(0));
		}
		
		function bufferToBase64String(dataBuffer) {
			return btoa(String.fromCharCode(...new _Uint8Array(dataBuffer)));
		}
		
		function getRandomBase64(numBytes) {
			const bytes= crypto.getRandomValues(new _Uint8Array(numBytes));
			return bufferToBase64String(bytes);
		}
		
		function encryptToBase64(keyString, saltString, nonceString, dataString) {
			const key= base64StringToBuffer(keyString);
			const salt= base64StringToBuffer(saltString);
			const nonce= base64StringToBuffer(nonceString);
			const derivedKey= hkdfDerive(salt, key, new _Uint8Array(), 32);
			
			const encoder= new TextEncoder("utf-8");
			const data= encoder.encode(dataString);
			
			const {cipherText, tag}= aeadEncrypt(derivedKey, nonce, data, new _Uint8Array());
			return {
				cipherString: bufferToBase64String(cipherText),
				tagString: bufferToBase64String(tag)
			};
		}
		
		function decryptFromBase64(keyString, saltString, nonceString, tagString, cipherString) {
			const key= base64StringToBuffer(keyString);
			const salt= base64StringToBuffer(saltString);
			const nonce= base64StringToBuffer(nonceString);
			const tag= base64StringToBuffer(tagString);
			const cipher= base64StringToBuffer(cipherString);
			const derivedKey= hkdfDerive(salt, key, new _Uint8Array(), 32);
			
			const plainText= aeadDecrypt(derivedKey, nonce, cipher, new _Uint8Array(), tag);
			
			if( plainText === null ) {
				return null;
			}
			
			const decoder= new TextDecoder('utf-8');
			return decoder.decode(plainText);
		}
		
		function renderSecuredPage( cipherData ) {
      const {
        nonce: nonceString,
        nextNonce: nextNonceString,
        salt: saltString,
        tag: tagString,
        data: cipherString
      }= cipherData;
			
			if(!cipherString || !nonceString || !nextNonceString || !saltString || !tagString) {
				fail('Missing encryption fields');
				return;
			}
			
			formNonceString= nextNonceString;
			
			const keyString= getOrPromptForKey();
			
			// Decrypt the json string
			const jsonString= decryptFromBase64(keyString, saltString, nonceString, tagString, cipherString);
			if( jsonString === null ) {
        clearKey();
				fail('Decryption error: wrong password');
			}
			
			// Set the values of all input fields transmitted
			const data= JSON.parse(jsonString);
			for(const fieldName in data) {
				const value= data[fieldName];
				if(typeof value === 'object') {
					continue;
				}
				
        // Find the input element and then access it again through the form element
        // This allows compatibility with radio buttons, as the form returns a
        // RadioNodeList, which is more useful
				const inputElement= _document.querySelector(`input[name=${fieldName}]`).form.elements[fieldName];
				if(inputElement) {
					if(inputElement.type === 'checkbox') {
						inputElement.checked= !!value;
					} else {
						inputElement.value= value;
					}
				}
			}
		}
    
		function submitForm( event ) {
      // TODO: show waiting state in UI
      
			event.preventDefault();
			const form= event.target;
      if( form.validatorFunction && !form.validatorFunction(form)) {
        return false;
      }
      
			const fieldObject= {};
			for(const field of form) {
				if(field.name && !field.hasAttribute('data-nosend')) {
					fieldObject[field.name]= field.type === 'checkbox' ? field.checked : field.value;
				}
			}
			const jsonString= JSON.stringify(fieldObject);
			
			const saltString= getRandomBase64(16);
			const keyString= getOrPromptForKey();
			
			const { cipherString, tagString }= encryptToBase64(keyString, saltString, formNonceString, jsonString);
			
			const request = new XMLHttpRequest();
			request.open("POST", "/api");
      request.setRequestHeader("Content-Type", "application/json");
			
      request.onerror= () => alert('Could not save settings: Unreachable');
			request.onload= () => {
        if( request.status === 200 ) {
          if( form.callbackFunction ) {
            form.callbackFunction( request );
            return;
          }
          
          const responseData= JSON.parse(request.responseText);
          formNonceString= responseData.nextNonce;          
          console.log('New nonce:', formNonceString);
          if( !formNonceString ) {
            fail('Server did not respond with nonce');
          }
          
          alert('Settings saved');
          return;
        }
        
        alert(`Could not save settings:\n${request.responseText}`);
      };
      
			request.send( JSON.stringify({
        nonce: formNonceString,
        salt: saltString,
        tag: tagString,
        data: cipherString
      }));
			
			return false;
		}
		
		function setupFormHandlers() {
			for(const form of _document.forms) {
				form.onsubmit= submitForm;
			}
      
      const restartForm= _document.getElementById("restart-form");
      restartForm.validatorFunction= () => {
        return confirm('Do you want to restart? Your configuration will be reloaded and changes will be permanent.');
      };
      restartForm.callbackFunction= () => {
        _window.setTimeout(() => alert('Restarting... Reload the page in ~30 seconds'), 200);
      };
      
      _document.getElementById("wifi-form").validatorFunction= form => {
        const elem= form.elements;
        const cond= elem.wifipwd.value === elem.repeatedpwd.value;
        if( !cond ) {
          alert('Wifi password fields do not match');
        }
        return cond;
      };
		}
		
		async function onPageLoaded() {
			if( _window.location.pathname === '/' ) {
        try {
          const cipherData= await fetch('/api').then( r => r.json() );
          renderSecuredPage( cipherData );
        } catch(e) {
          console.error(e);
          alert('Could not load settings data');
        }
        
				setupFormHandlers();
        
        _document.getElementById('logout-button').onclick= () => {
          clearKey();
          _window.location.href= '/';
        };
			}
		}
		
		_document.addEventListener('DOMContentLoaded', onPageLoaded);
		
	})();
	
})();
