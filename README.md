# krb-certsign

`krb-certsign` is an HTTP server that takes Kerberos credentials and signs
certificates.

Kubernetes [does not natively support Kerberos for authentication][kube-auth],
but it does support using X509 client certificates. This lets us bridge the two.
Users authenticate with Kerberos and provide their public key, and the service
returns a signed certificate, authenticating the user and the LDAP groups
they're in.

# Why Kerberos and not LDAP?
Kerberos works better for Kubernetes since we can integrate it with our already
existing infrastructure of getting tickets and using them to access services. If
we combine this with [client-go credential plugins][client-go], users can
seamlessly authenticate to Kubernetes without having to type in their password
each time.

[client-go]: https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins
[kube-auth]: https://kubernetes.io/docs/reference/access-authn-authz/authentication/
