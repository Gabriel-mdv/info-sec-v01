from functools import wraps
from flask import redirect, url_for, session

def require_2fa(view_func):
    # Decorator that ensures user is logged in and has passed 2FA.
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        print("[DEBUG] require_2fa check: user_id =", session.get("user_id"), " verified_2fa =", session.get("verified_2fa"))
        if "user_id" not in session:
            # check if he is not even logged int to make sure and send back to login
            return redirect(url_for("login"))
        
        if not session.get("verified_2fa"):
            # when logged in but not verified 2fa, send to 2fa page
            return redirect(url_for("two_factor_auth"))
        
        return view_func(*args, **kwargs)
    return wrapped_view


# def require_2fa(view_func):
#     @wraps(view_func)
#     def wrapped_view(*args, **kwargs):
#         print("[DEBUG] require_2fa check: user_id =", session.get("user_id"), " verified_2fa =", session.get("verified_2fa"))
#         if "user_id" not in session:
#             return redirect(url_for("login"))
#         if not session.get("verified_2fa"):
#             return redirect(url_for("two_factor_auth"))
#         return view_func(*args, **kwargs)
#     return wrapped_view
