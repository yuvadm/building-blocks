import base64
import hmac, hashlib

POLICY = """{"expiration": "2012-01-01T00:00:00Z",
  "conditions": [
    {"bucket": "AWS_BUCKET_NAME"}, 
    ["starts-with", "$key", "uploads/"],
    {"acl": "private"},
    {"success_action_redirect": "/"},
    ["starts-with", "$Content-Type", ""],
    ["content-length-range", 0, 1048576]
  ]
}"""

KEY = "AWS_SECRET_KEY"

policy = base64.b64encode(POLICY)

sig = base64.b64encode(hmac.new(KEY, policy, hashlib.sha1).digest())

print sig

##################
### Or use: http://s3.amazonaws.com/doc/s3-example-code/post/post_sample.html
##################