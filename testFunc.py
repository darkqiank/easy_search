def function_b(name, age, b):
    print("Arguments in function_b:")
    print("name:", name)
    print("age:", age)
    print("b:", b)


def function_a(*args, **kwargs):
    print("Arguments in function_a:")
    print("Positional arguments:", args)
    print("Keyword arguments:", kwargs)

    # Call function_b and pass all arguments received by function_a
    function_b(*args, **kwargs)


# Example usage:
function_a(name="Alice", age=30, b=45)