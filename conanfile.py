from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain
from os import environ, path, symlink


class Recipe(ConanFile):
    name = "sysapi_tls"
    version = "1.3.0"
    license = "<VW.os license>"
    url = "https://git.hub.vwgroup.com/swp-vwos/vwos-sysapi_tls.git"
    description = "System API TLS library"
    topics = ("VW.os", "Autosar", "Adaptive", "sysapi_tls")

    settings = "os", "arch", "compiler", "build_type", "vwos_build_mode"

    # Note: preserve scm attribute formatting
    scm = {"revision": "auto",
           "subfolder": ".",
           "type": "git",
           "url": "auto"}
    revision_mode = "scm"

    generators = "CMakeDeps"

    options = {
        "gtest": [True, False],
    }
    default_options = {
        "gtest": False,
    }

    def requirements(self):
        self.requires("vwos-wolfssl/[~1.0.0]@vwos/testing")
        self.requires("vwos-mid-vector-amsr/[~1.6.0]@vwos/integration")
    
    def build_requirements(self):
        self.test_requires("gtest/[~1.11.0]@vwos/integration")
        self.tool_requires("vwos-mid-clang-tools/[^1.0.0]@vwos/integration")
        self.tool_requires("vwos-mid-parasoft-tools/[^1.0.0]@vwos/integration")

    def layout(self):
        self.folders.build = "build_lib"
        self.folders.generators = path.join(self.folders.build, "conan")
        self.folders.source = "tlsAPI-WS"

    def generate(self):
        tc = CMakeToolchain(self)
        tc.cache_variables["CONAN_PKG_NAME"] = self.name
        tc.cache_variables["CONAN_PKG_VERSION"] = self.version
        tc.cache_variables['ENABLE_UNIT_TESTS'] = self.options.gtest
        if self.settings.os == "Neutrino":
            tc.cache_variables["ARCH_ARM_LINUX"] = "ON"
        tc.generate()

    def build(self):
        cmake = CMake(self)
        if self.settings.os == "Neutrino":
            environ["CC"] = "qcc"
            environ["CFLAGS"] = "-Vgcc_ntoaarch64le"
            environ["CXX"] = "q++"
            environ["CXXFLAGS"] = "-Vgcc_ntoaarch64le"
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.install()
        self.copy("deploy/*")

    def package_info(self):
        self.cpp_info.set_property("cmake_find_mode", "module")
        self.cpp_info.set_property("cmake_file_name", f"{self.name}")
        self.cpp_info.set_property("cmake_target_name", f"{self.name}::{self.name}")
        self.cpp_info.set_property("pkg_config_name", f"{self.name}")
        self.cpp_info.libs.append(f"{self.name}")
        self.cpp_info.libdirs = ["lib", "lib/sysapi"]
        self.cpp_info.system_libs.append("dl") 

