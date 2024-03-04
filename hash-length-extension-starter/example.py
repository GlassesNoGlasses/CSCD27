import hlextend
m = b'This is the end of the message'
sha2 = hlextend.new('sha256')
sha2.hash(m)
print(sha2.hexdigest())

sha2 = hlextend.new('sha256')
x = b'Or maybe not!'
sha2.extend("a83e67060b10710f6e0631d37a76179ae97073a516ff7ac46002d427f50b436c", x)
print(sha2.hexdigest())

sha2 = hlextend.new('sha256')
sha2.hash(m + sha2.padding(len(m)) + x)
print(sha2.hexdigest())


sha2 = hlextend.new('sha256')
sha2.hash(b'abcd')
print(sha2.hexdigest())


sha2 = hlextend.new('sha256')
sha2.hash(b'dcba')
print(sha2.hexdigest())

# hash(k + m)

# hash(k + m + padding(len(m) + len(k)) + x)
# <=> extend(token, x)


# 73b26d4c89fef5300ca3cb403011e78c499e6f299b94b7d73483ce1c897638f4
