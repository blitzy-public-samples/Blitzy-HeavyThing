include 'settings.inc'
include '../../ht.inc'

include '../../ht_data.inc'

; --- Re-export EXISTING data labels (no prolog → not auto-public) so the C KAT
; --- drivers can link to them. This neither renames, wraps, nor moves any
; --- falign-prefixed crypto label; it only sets ELF visibility of labels that
; --- already exist in ht.inc. Required by kat_dh_pool.c and kat_aes.c.
public dh$pool_p
public dh$pool_g
public aes$tls
