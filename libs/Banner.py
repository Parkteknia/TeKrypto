import base64

def get_banner(version):

    tbanner = '''
     _____    _  __                 _        _
    |_   _|__| |/ /_ __ _   _ _ __ | |_ ___ | |
      | |/ _ \ ' /| '__| | | | '_ \| __/ _ \| |
      | |  __/ . \| |  | |_| | |_) | || (_) |_|
      |_|\___|_|\_\_|   \__, | .__/ \__\___/(_)
                        |___/|_|

       TeKrypto v'''+version+''' by Arteknia.org - 2020
    '''

    sample_string_bytes = tbanner.encode("ascii")

    base64_bytes = base64.b64encode(sample_string_bytes)
    base64_string = base64_bytes.decode("ascii")

    return base64_string
