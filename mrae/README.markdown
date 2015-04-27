# Misuse-resistant deterministic AEAD

(With, as yet, unproven security.)

Goals:
  - A fully deterministic encryption system.
  - But still a valid AONT in the indifferentiability framework.

These imply maximal misuse-resistance.


```py
   S = 32      # security strength
   TAGLEN = 24 # probability of a forgery not being detected early
   BKLEN  = 32 # the key-length of the block cipher

  def derivekn(n):
    # Using this as the KDF, rather than a hash function, likely
    # implies some related-key condition on the stream cipher.
    k = n
    n = k[0:8] ^ k[8:16] ^ k[16:24] ^ k[24:32]
    return (k, n)

  def mr_encrypt(key, ad, m):
    aont_iv = vecmac(key, m, ds=ds_aont_iv, outlen=S)

    aont_n    = vecmac(key, [ad, m], ds=ds_aont_nk, outlen=S)
    aont_ck, aont_cn = derivekn(aont_n)
    aont_c    = streamxor(k=aont_ck, n=aont_cn, m)
    aont_mask = vecmac(key, [ad, aont_c], ds_aont_mask, outlen=TAGLEN)

    aont_maskedk = xor(aont_iv, aont_mask)
    aont_tz = [0]*TAGLEN + aont_maskedk

    ecb_k = vecmac(key, [aont_tz, ad], ds=ds_ecb_k, outlen=KLEN)
    ecb_maskedk = ecb_encrypt(ecb_k, aont_maskedk)
    ecb_c = ecb_encrypt(ecb_k, aont_c)
    ecb_t = vecmac(key, [ecb_maskedk, ad, ecb_c], ds=ds_ecb_t, outlen=TAGLEN)
    
    c = ecb_c
    t = ecb_maskedk + ecb_t
    return aont_tz + 

  def mr_decrypt(key, ad, c, t):
    aont_maskedk, ecb_t = t[:S], t[S:]
    ecb_k = vecmac(key, [aont_maskedk, ad, 

```
