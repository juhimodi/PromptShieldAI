# # # import streamlit as st

# # # # Hardcoded credentials
# # # USERNAME = "admin"
# # # PASSWORD = "cyber123"

# # # def login():

# # #     st.title("🔐 Secure Login")

# # #     username = st.text_input("Username")

# # #     password = st.text_input(
# # #         "Password",
# # #         type="password"
# # #     )

# # #     login_button = st.button("Login")

# # #     if login_button:

# # #         if username == USERNAME and password == PASSWORD:

# # #             st.session_state["authenticated"] = True

# # #             st.success("Login Successful")

# # #             st.rerun()

# # #         else:

# # #             st.error("Invalid Credentials")
# # import os
# # import streamlit as st

# # _USERNAME = os.getenv("PS_USERNAME", "admin")
# # _PASSWORD = os.getenv("PS_PASSWORD", "cyber123")


# # def login():
# #     """Render the login form and set session state on success."""
# #     st.markdown(
# #         "<h2 style='text-align:center'>🔐 PromptShield AI — Secure Login</h2>",
# #         unsafe_allow_html=True,
# #     )
# #     col1, col2, col3 = st.columns([1, 2, 1])
# #     with col2:
# #         username = st.text_input("Username", placeholder="Enter username")
# #         password = st.text_input("Password", type="password", placeholder="Enter password")
# #         if st.button("Login", use_container_width=True):
# #             if username == _USERNAME and password == _PASSWORD:
# #                 st.session_state["authenticated"] = True
# #                 st.rerun()
# #             else:
# #                 st.error("Invalid credentials. Please try again.")


# # def logout():
# #     """Clear session and rerun."""
# #     st.session_state["authenticated"] = False
# #     st.rerun()cd C:\Users\Admin\Desktop\LLM\promptShieldAI
# # Invoke-WebRequest -Uri "https://raw.githubusercontent.com/streamlit/streamlit/develop/README.md" -ErrorAction SilentlyContinue | Out-Null
# import os
# import streamlit as st

# _USERNAME = os.getenv("PS_USERNAME", "admin")
# _PASSWORD = os.getenv("PS_PASSWORD", "cyber123")


# def login():
#     """Render the login form and set session state on success."""
#     st.markdown(
#         "<h2 style='text-align:center'>🔐 PromptShield AI — Secure Login</h2>",
#         unsafe_allow_html=True,
#     )
#     col1, col2, col3 = st.columns([1, 2, 1])
#     with col2:
#         username = st.text_input("Username", placeholder="Enter username")
#         password = st.text_input("Password", type="password", placeholder="Enter password")
#         if st.button("Login", use_container_width=True):
#             if username == _USERNAME and password == _PASSWORD:
#                 st.session_state["authenticated"] = True
#                 st.rerun()
#             else:
#                 st.error("Invalid credentials. Please try again.")


# def logout():
#     """Clear session and rerun."""
#     st.session_state["authenticated"] = False
#     st.rerun()

import os
import streamlit as st

_USERNAME = os.getenv("PS_USERNAME", "admin")
_PASSWORD = os.getenv("PS_PASSWORD", "cyber123")


def login():
    """Render the login form and set session state on success."""
    st.markdown(
        "<h2 style='text-align:center'>🔐 PromptShield AI — Secure Login</h2>",
        unsafe_allow_html=True,
    )
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        username = st.text_input("Username", placeholder="Enter username")
        password = st.text_input("Password", type="password", placeholder="Enter password")
        if st.button("Login", use_container_width=True):
            if username == _USERNAME and password == _PASSWORD:
                st.session_state["authenticated"] = True
                st.rerun()
            else:
                st.error("Invalid credentials. Please try again.")


def logout():
    """Clear session and rerun."""
    st.session_state["authenticated"] = False
    st.rerun()