use crate::guards;

pub fn make_location(
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
) -> Option<rolodex_grpc::proto::Location> {
    if let Some(location) = geo_headers {
        Some(rolodex_grpc::proto::Location {
            ip_address: client_ip.0,
            region: location.region,
            region_subdivision: location.region_subdivision,
            city: location.city,
        })
    } else {
        Some(rolodex_grpc::proto::Location {
            ip_address: client_ip.0,
            region: "unknown".into(),
            region_subdivision: "unknown".into(),
            city: "unknown".into(),
        })
    }
}
