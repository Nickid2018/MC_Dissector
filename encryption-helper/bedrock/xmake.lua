set_toolchains("msvc")
add_repositories("liteldev-repo https://github.com/LiteLDev/xmake-repo.git")
add_requires("libhat 0.4.0")
add_requires("minhook v1.3.4")
target("encryption-helper")
    set_kind("shared")
    add_files("src/**.cpp")
    set_languages("cxx23")
    set_symbols("debug")
    add_defines(
        "NOMINMAX",
        "UNICODE",
        "_HAS_CXX23=1",
        "_AMD64_"
    )
    add_packages("libhat")
    add_packages("minhook")