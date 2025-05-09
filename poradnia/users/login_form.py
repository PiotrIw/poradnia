from allauth.account.forms import LoginForm
from atom.ext.crispy_forms.forms import SingleButtonMixin
from crispy_forms.bootstrap import PrependedText
from crispy_forms.layout import Layout
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy as _l


class CustomLoginForm(SingleButtonMixin, LoginForm):
    action_text = _l("Sign In")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["login"].label = _("Login")
        self.helper.form_class = "login-form"
        self.helper.layout = Layout(
            PrependedText("login", '<i class="fas fa-user"></i>'),
            PrependedText("password", '<i class="fas fa-key"></i>', type="password"),
        )
