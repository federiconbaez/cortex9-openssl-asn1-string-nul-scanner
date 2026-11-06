# Sources

All files were fetched once and read offline. The SHA-256 hashes are of
the local copies.

| File | Origin | SHA-256 |
|---|---|---|
| OpenSSL Security Advisory [24 August 2021] (text) | https://www.openssl.org/news/secadv/20210824.txt | 66334c85ddd9c930da8fe00ca3eaff4182ef23553e0a3eadf85842e9a513e5bb |
| NVD CVE-2021-3712 JSON | services.nvd.nist.gov | 240a55d33bd589d085b254112d607ec6eb84eb014e83b1b24523bf03ffcb6f6d |
| d9d838ddc0ed.diff (t_x509.c) | github.com/openssl/openssl commit d9d838ddc0ed083fb4c26dd067e71aad7c65ad16 | 8215b51c29695b3e7926688eeb9d5b795484ac910707060b7fdcdf62f87be9f7 |
| 174ba8048a7f.diff (v3_alt.c, v3_utl.c) | 174ba8048a7f2f5e1fca31cfb93b1730d9db8300 | 91236334031c9d4997ad32dfe7321691a02d60403541b3a216f71e1533c70840 |
| 5f54e57406ca.diff (v3_cpols.c) | 5f54e57406ca17731b9ade3afd561d3c652e07f2 | 97036157cf103dc97387ddfbef8edb258eded3dd783dba3314fdf178188c6134 |
| 23446958685a.diff (v3_pci.c) | 23446958685a593d4d9434475734b99138902ed2 | b12d36295c49adc94d844d5ada6040106616f0dfd702befda686f71bc6e7e9fd |
| 8393de42498f.diff (v3_ncons.c) | 8393de42498f8be75cf0353f5c9f906a43a748d2 | 9dda511089dfa0fb1c7660d0f7e468bb8e111b3fbab1105c797156fbbba3289e |
| bb4d2ed40914.diff (v3_utl.c append_ia5) | bb4d2ed4091408404e18b3326e3df67848ef63d0 | 6d2b5e30ccbffaa12ccf1f2feba3314b36fdc7846c1514ce64b3ff7b82281476 |
| 2d0e5d4a4a5d.diff (t_spki.c) | 2d0e5d4a4a5d4332325b5e5cea492fad2be633e1 | 03beb8c1882a7207fba849923de9f230efc3a1665193b49ae959475b20a8cb04 |
| 5478387c14e0.diff (ts_verify_ctx.c) | 5478387c14e0c22a525e2ec5ed37f6ffad4b7c59 | 73c76650cf1a07e6cf5a72eac4684efb04cccdb912fa26209c09ac44b1907c8e |
| 4de66925203c.diff (x509_time_test.c, a test) | 4de66925203ca99189c842136ec4a623137ea447 | 1f42cf0da07bcb6deac163439df00dd25c53e15a97bac5747a5be55fc9b3ff7c |

`fixtures/upstream/commits.txt` lists each fix commit with its parent and
the files it changed. `fixtures/upstream/SHA256SUMS` covers the vendored
pre/post `.c` files, which were fetched from
`raw.githubusercontent.com/openssl/openssl/<sha>/<path>`.
`LICENSE.OpenSSL` was fetched at d9d838ddc0ed (SHA-256
c32913b33252e71190af2066f08115c69bc9fddadf3bf29296e20c835389841c).
