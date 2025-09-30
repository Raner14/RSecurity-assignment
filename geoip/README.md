# GeoIP Database

This folder should contain the **GeoLite2-Country.mmdb** file.

## How to download and place the database

1. Go to the MaxMind GeoLite2 free databases page:  
   [https://dev.maxmind.com/geoip/geolite2-free-geolocation-data](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

2. **Sign up** for a free MaxMind account (GeoLite requires registration):
   - Fill in your name, email, and basic details.
   - Confirm your email address if requested.

3. After logging in, navigate to **Download Databases** in your account dashboard.

4. Download the database called **GeoLite2 Country** in **GeoIP2 Binary (.mmdb)** format (usually provided as a `.tar.gz` or `.zip` archive).

5. Extract the archive file until you get:  
   `GeoLite2-Country.mmdb`

6. Place the file **directly inside this folder** (`geoip/`) so the structure looks like this:

RSecurity-assignment-main/
├─ src/
├─ data/
├─ outputs/
├─ geoip/
│ └─ GeoLite2-Country.mmdb ✅
└─ README.md