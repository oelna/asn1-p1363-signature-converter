# ASN.1 / P1363 ECDSA Signature Converter
Convert between ASN.1 and P1363 ECDSA signature formats in Javascript. The functions `p1363_to_asn1()` and `asn1_to_p1363()` take an `arrayBuffer` as input and return an `arrayBuffer`, so you may need to convert your data before and after, eg. from Hex or Base64 encoding. 

**I would love to get feedback on this, especially if it works for you, since I only tested a few samples.**

```javascript
import { p1363_to_asn1, asn1_to_p1363 } from './asn1-p1363.js';

let asn1, asn1AB, p1363, p1363AB;

asn1 = 'MEYCIQCwcPGaPYkgYsFytXR6qmz/zuqMA2ihetZJw7JwzMRPJQIhAMH+mpGVTMdOEHClFcGMt2d1ujjne/JT4cSUzw1tRl87';
asn1AB = Uint8Array.from(atob(asn1), c => c.charCodeAt(0)).buffer;

p1363AB = asn1_to_p1363(asn1AB);
p1363 = window.btoa(String.fromCharCode.apply(null, new Uint8Array(p1363AB)));
console.log('P1363', p1363);

// or

p1363 = 'sHDxmj2JIGLBcrV0eqps/87qjANooXrWScOycMzETyXB/pqRlUzHThBwpRXBjLdndbo453vyU+HElM8NbUZfOw==';
p1363AB = Uint8Array.from(atob(p1363), c => c.charCodeAt(0)).buffer;

asn1AB = asn1_to_p1363(p1363AB);
asn1 = window.btoa(String.fromCharCode.apply(null, new Uint8Array(asn1AB)));
console.log('ASN1', asn1);
```
