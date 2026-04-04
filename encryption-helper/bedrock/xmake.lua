set_toolchains("msvc")
package("blook")
    set_description("A modern C++ library for hacking.")
    set_license("GPL-3.0")
    add_urls("https://github.com/std-microblock/blook.git")
    add_configs("shared", {description = "Build shared library.", default = false, type = "boolean", readonly = true})
    if is_plat("windows") then
        add_syslinks("advapi32")
    end
    add_deps("zasm")
    on_install("windows", function (package)
        import("package.tools.xmake").install(package, {}, {target = "blook"})
    end)
package_end()
add_requires("blook 721f6dcc0c6e2b4c370bf927de31f582e1099de3")
target("encryption-helper")
    set_license("GPL-3.0")
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
    add_packages("blook")