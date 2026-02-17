"""Unit tests — run against safe/mock targets only."""
import pytest
from unittest.mock import patch, MagicMock
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.email_recon import validate_email_format
from modules.domain_recon import dns_enum

class TestEmailRecon:
    def test_valid_email(self):
        assert validate_email_format("user@example.com") is True

    def test_invalid_email_no_at(self):
        assert validate_email_format("userexample.com") is False

    def test_invalid_email_no_dot(self):
        assert validate_email_format("user@examplecom") is False

class TestDomainRecon:
    @patch("modules.domain_recon.dns.resolver.Resolver")
    def test_dns_enum_returns_dict(self, mock_resolver):
        mock_resolver.return_value.resolve.side_effect = Exception("mocked")
        result = dns_enum("example.com")
        assert isinstance(result, dict)
        assert "A" in result
```

---

### 📄 `wordlists/subdomains.txt`
```
www
mail
ftp
admin
api
dev
staging
test
vpn
remote
portal
shop
blog
cdn
app
```

---

### 📄 `.gitignore`
```
results/
config/config.yaml
__pycache__/
*.pyc
.env
*.log
