import pycountry

def alpha2_to_alpha3(alpha2):
    country = pycountry.countries.get(alpha_2=alpha2)
    return country.alpha_3 if country else None