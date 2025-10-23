ROLE_BASIC = 'basic'
ROLE_USER_ADMIN = 'user_admin'
ROLE_DATA_ADMIN = 'data_admin'

policy = {
"upload_own_file": ROLE_BASIC, # done
"download_own_file": ROLE_BASIC, # done
"delete_own_file": ROLE_BASIC, # done
"change_password": ROLE_BASIC, # done
"create_user": ROLE_USER_ADMIN, # done
"delete_user": ROLE_USER_ADMIN, # progress
"assign_role": ROLE_USER_ADMIN, # assign role to user
"change_username": ROLE_USER_ADMIN, # done

"download_any_file": ROLE_DATA_ADMIN,
"delete_any_file": ROLE_DATA_ADMIN,

"read_log_file": ROLE_USER_ADMIN, # either admin role can read logs
"read_log_file": ROLE_DATA_ADMIN,
}



