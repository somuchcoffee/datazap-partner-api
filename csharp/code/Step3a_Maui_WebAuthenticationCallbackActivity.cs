using Android.App;
using Android.Content;
using Android.Content.PM;
using Microsoft.Maui.Authentication;

[Activity(NoHistory = true, LaunchMode = LaunchMode.SingleTop, Exported = true)]
[IntentFilter(new[] { Intent.ActionView },
    Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable },
    DataScheme = "com.yourcompany.yourapp", DataHost = "datazap")]
public class WebAuthenticationCallbackActivity : WebAuthenticatorCallbackActivity
{
}
