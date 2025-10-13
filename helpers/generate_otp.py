
# _____________ generate otp chain ___________________--

def generate_otp(user_id, conn):
    import datetime, hashlib

    now = datetime.datetime.utcnow()
    base_time = now.replace(second=0, microsecond=0)

    # generatte OTP chaain for 24 hours
    for i in range(1440):
        otp_time = base_time + datetime.timedelta(minutes=i)
        timespamp = int(otp_time.strftime("%Y%m%d%H%M"))

        # generate OTP USING THE HASH
        seed = f"user_{user_id}_otp_seed_{timespamp}".encode()
        hash_result = hashlib.sha256(seed).hexdigest()
        otp_code = int (hash_result[:6], 16) % 1000000  # 6-digit OTP
        otp_code = f"{otp_code:06d}"

        # store the OTP IN DB
        conn.execute(
            "INSERT INTO otp_chain (user_id, timestamp, otp) VALUES (?, ?, ?)",
            (user_id, timespamp, otp_code)
        )
 
    return True