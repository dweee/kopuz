if [ -d "${CARGO_TARGET_DIR:-target}" ]; then
  find "${CARGO_TARGET_DIR:-target}" -type d \
    -path '*/build/opusic-sys-*/out/build' -prune -exec rm -rf -- {} +
fi
