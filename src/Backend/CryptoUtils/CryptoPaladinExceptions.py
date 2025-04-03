

class SaltLengthException(Exception):
    def __init__(self, expected_size, size):            
        # Call the base class constructor with the parameters it needs
        message = "Wrong Salt length expected length of {elen} but got {alen}".format(elen=expected_size,alen=size)
        super().__init__(message)