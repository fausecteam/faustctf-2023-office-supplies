FROM faust.cs.fau.de:5000/office_supplies_buildenv as build
WORKDIR /build
COPY Cargo.toml  .
COPY src src
COPY .cargo .cargo
COPY vendor vendor
RUN cargo build --offline --release

FROM faust.cs.fau.de:5000/office_supplies_deps

COPY --from=build /build/target/release/office-supplies /app/
COPY cleanup.sh /app/cleanup.sh
COPY quotes.txt /app/quotes.txt
RUN chmod 700 /app/cleanup.sh
RUN chmod 444 /app/quotes.txt

WORKDIR /app
ENTRYPOINT /app/cleanup.sh & mkdir -p /app/data/objects && chmod 777 /app/data/objects && socat -6 tcp-listen:1337,fork,reuseaddr EXEC:/app/office-supplies
EXPOSE 1337/tcp
