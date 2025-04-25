set(CMAKE_PROJECT_TARGET rabe-cpp)

# ------------------------------------------------------------------------------
# Build Rust Attribute Based Encryption (RABE) library
# ------------------------------------------------------------------------------

set(CARGO_FLAGS --release)
set(RABE_RUST_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/../target/release/libaccless_rabe.a" CACHE INTERNAL "")
if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    set(CARGO_FLAGS --release --target=wasm32-wasip1)
    set(RABE_RUST_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/../target/wasm32-wasip1/release/libaccless_rabe.a" CACHE INTERNAL "")
endif ()

add_library(rabe_rust_lib STATIC IMPORTED GLOBAL)

add_custom_command(
    OUTPUT ${RABE_RUST_LIBRARY}
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR}/../target cargo build
        --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/../Cargo.toml
        ${CARGO_FLAGS}
    COMMENT "Building rabe staticlib with Cargo"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
)

add_custom_target(rabe_rust_build DEPENDS ${RABE_RUST_LIBRARY})

set_target_properties(rabe_rust_lib PROPERTIES
    IMPORTED_LOCATION ${RABE_RUST_LIBRARY}
)

add_dependencies(rabe_rust_lib rabe_rust_build)

# ------------------------------------------------------------------------------
# Build CPP bindings
# ------------------------------------------------------------------------------

add_library(${CMAKE_PROJECT_TARGET} rabe.cpp aes.cpp)
target_link_libraries(${CMAKE_PROJECT_TARGET} PUBLIC rabe_rust_lib)
add_library(accless::rabe ALIAS ${CMAKE_PROJECT_TARGET})
