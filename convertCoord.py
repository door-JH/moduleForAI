from pyproj import Proj, transform

#네이버지도 기준
def wgsTo5179(x, y):
    origin_coordinate = Proj(proj = 'latlong',datum = 'WGS84')

    transform_coordinate = Proj(init='epsg:5179')

    lng, lat = transform(origin_coordinate, transform_coordinate, x, y)

    return lng, lat

def wgsFrom5179(x, y):
    origin_coordinate = Proj(init='epsg:5179')

    transform_coordinate = Proj(proj = 'latlong',datum = 'WGS84')

    lng, lat = transform(origin_coordinate, transform_coordinate, x, y)

    return lng, lat


#카카오지도 기준
def wgsTo5181(x, y):
    origin_coordinate = Proj(proj = 'latlong',datum = 'WGS84')

    transform_coordinate = Proj(init='epsg:5181')

    lng, lat = transform(origin_coordinate, transform_coordinate, x, y)

    return lng, lat

def wgsFrom5181(x, y):
    origin_coordinate = Proj(init='epsg:5181')

    transform_coordinate = Proj(proj = 'latlong',datum = 'WGS84')

    lng, lat = transform(origin_coordinate, transform_coordinate, x, y)

    return lng, lat

#구글지도 기준
def wgsTo3857(x, y):
    origin_coordinate = Proj(proj = 'latlong',datum = 'WGS84')

    transform_coordinate = Proj(init='epsg:3857')

    lng, lat = transform(origin_coordinate, transform_coordinate, x, y)

    return lng, lat

def wgsFrom3857(x, y):
    origin_coordinate = Proj(init='epsg:3857')

    transform_coordinate = Proj(proj = 'latlong',datum = 'WGS84')

    lng, lat = transform(origin_coordinate, transform_coordinate, x, y)

    return lng, lat


