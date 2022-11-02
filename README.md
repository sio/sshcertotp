# Issue ssh certificate after asking for TOTP key


## Known problems

### Denial of service: TOTP rate limit exhaustion

If attacker knows both your username and sshcertotp endpoint they may
trivially cause denial of service by supplying incorrect TOTP values more
frequently than allowed by TOTP validator rate limits. Until TOTP validation
attempt rate returns under the limit even correct TOTP values coming from a
legitimate user will not be accepted and certificates will not be issued for
this user.

If this is a problem in your use case, consider adding another authentication
factor before TOTP (password / IP allow list / messenger bot / etc).
To do that place your extra logic right after `term.ReadPassword()` call.
