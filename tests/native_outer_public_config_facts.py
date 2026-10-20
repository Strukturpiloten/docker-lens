"""Reviewed public image-config facts for offline source-authority controls.

Values are metadata from the eight audited canonical OCI image chains (same
semantics on both architectures), not copied oracle implementation code. No
rootfs/account payload, raw runtime OCI or private consumer context is stored.
Account audit receipt: ab61771e18c56e68ebcaf76e394a0d2466cda97edcecf14f0a44300777b35859.
This data does not establish executable provenance or native qualification.
"""

PUBLIC_CONFIG = {
    "upstream-rootful": {
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "DOCKER_HOST=unix:///var/run/docker.sock"
        ],
        "Cmd": [
            "/usr/local/bin/start-dockerd"
        ],
        "Volumes": {
            "/var/lib/docker": {}
        },
        "WorkingDir": "/",
        "Labels": {
            "org.opencontainers.image.base.digest": "sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6",
            "org.opencontainers.image.base.name": "docker.io/library/alpine:3.24",
            "org.opencontainers.image.created": "2026-09-27T19:57:58Z",
            "org.opencontainers.image.description": "Upstream Docker Engine 29.8.1 static payload on maintained Alpine, rootful daemon",
            "org.opencontainers.image.documentation": "https://github.com/Strukturpiloten/containers/tree/0b136a13a8bb612d91960ae5d07e72f449c89ec1/images/docker/docker-29-rootful",
            "org.opencontainers.image.licenses": "AGPL-3.0-only",
            "org.opencontainers.image.revision": "0b136a13a8bb612d91960ae5d07e72f449c89ec1",
            "org.opencontainers.image.source": "https://github.com/Strukturpiloten/containers",
            "org.opencontainers.image.title": "Docker Engine 29 rootful",
            "org.opencontainers.image.url": "https://github.com/Strukturpiloten/containers/pkgs/container/docker-29-rootful",
            "org.opencontainers.image.vendor": "Strukturpiloten OHG",
            "org.opencontainers.image.version": "29.8.1"
        }
    },
    "upstream-rootless": {
        "User": "docker",
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/home/docker",
            "XDG_RUNTIME_DIR=/run/user/1000",
            "DOCKER_HOST=unix:///run/user/1000/docker.sock",
            "DOCKERD_ROOTLESS_ROOTLESSKIT_NET=slirp4netns"
        ],
        "Cmd": [
            "/usr/local/bin/start-dockerd"
        ],
        "Volumes": {
            "/home/docker/.local/share/docker": {}
        },
        "WorkingDir": "/",
        "Labels": {
            "org.opencontainers.image.base.digest": "sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6",
            "org.opencontainers.image.base.name": "docker.io/library/alpine:3.24",
            "org.opencontainers.image.created": "2026-09-27T19:57:58Z",
            "org.opencontainers.image.description": "Upstream Docker Engine 29.8.1 static payload on maintained Alpine, rootless daemon",
            "org.opencontainers.image.documentation": "https://github.com/Strukturpiloten/containers/tree/0b136a13a8bb612d91960ae5d07e72f449c89ec1/images/docker/docker-29-rootless",
            "org.opencontainers.image.licenses": "AGPL-3.0-only",
            "org.opencontainers.image.revision": "0b136a13a8bb612d91960ae5d07e72f449c89ec1",
            "org.opencontainers.image.source": "https://github.com/Strukturpiloten/containers",
            "org.opencontainers.image.title": "Docker Engine 29 rootless",
            "org.opencontainers.image.url": "https://github.com/Strukturpiloten/containers/pkgs/container/docker-29-rootless",
            "org.opencontainers.image.vendor": "Strukturpiloten OHG",
            "org.opencontainers.image.version": "29.8.1"
        }
    },
    "debian11-rootful": {
        "User": "root",
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/root",
            "XDG_RUNTIME_DIR=/run",
            "DOCKER_HOST=unix:///var/run/docker.sock"
        ],
        "Cmd": [
            "/usr/local/bin/start-dockerd"
        ],
        "Volumes": {
            "/var/lib/docker": {}
        },
        "Labels": {
            "org.opencontainers.image.base.digest": "sha256:6f519a81440354a85eb592c5f32109ab80605f6b892455983a6f618bf87fabe9",
            "org.opencontainers.image.base.name": "docker.io/library/debian:11",
            "org.opencontainers.image.created": "2026-09-27T19:57:58Z",
            "org.opencontainers.image.description": "Native Debian 11 docker.io package with rootful Docker daemon for isolated compatibility tests",
            "org.opencontainers.image.documentation": "https://github.com/Strukturpiloten/containers/tree/0b136a13a8bb612d91960ae5d07e72f449c89ec1/images/docker/docker-debian-11-rootful",
            "org.opencontainers.image.licenses": "AGPL-3.0-only",
            "org.opencontainers.image.revision": "0b136a13a8bb612d91960ae5d07e72f449c89ec1",
            "org.opencontainers.image.source": "https://github.com/Strukturpiloten/containers",
            "org.opencontainers.image.title": "Docker Engine Debian 11 rootful",
            "org.opencontainers.image.url": "https://github.com/Strukturpiloten/containers/pkgs/container/docker-debian-11-rootful",
            "org.opencontainers.image.vendor": "Strukturpiloten OHG",
            "org.opencontainers.image.version": "1.0.0"
        }
    },
    "debian11-rootless": {
        "User": "1000:1000",
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/home/docker",
            "XDG_RUNTIME_DIR=/run/user/1000",
            "DOCKER_HOST=unix:///run/user/1000/docker.sock"
        ],
        "Cmd": [
            "/usr/local/bin/start-dockerd"
        ],
        "Volumes": {
            "/home/docker/.local/share/docker": {}
        },
        "Labels": {
            "org.opencontainers.image.base.digest": "sha256:6f519a81440354a85eb592c5f32109ab80605f6b892455983a6f618bf87fabe9",
            "org.opencontainers.image.base.name": "docker.io/library/debian:11",
            "org.opencontainers.image.created": "2026-09-27T19:57:58Z",
            "org.opencontainers.image.description": "Native Debian 11 docker.io package with rootless Docker daemon for isolated compatibility tests",
            "org.opencontainers.image.documentation": "https://github.com/Strukturpiloten/containers/tree/0b136a13a8bb612d91960ae5d07e72f449c89ec1/images/docker/docker-debian-11-rootless",
            "org.opencontainers.image.licenses": "AGPL-3.0-only",
            "org.opencontainers.image.revision": "0b136a13a8bb612d91960ae5d07e72f449c89ec1",
            "org.opencontainers.image.source": "https://github.com/Strukturpiloten/containers",
            "org.opencontainers.image.title": "Docker Engine Debian 11 rootless",
            "org.opencontainers.image.url": "https://github.com/Strukturpiloten/containers/pkgs/container/docker-debian-11-rootless",
            "org.opencontainers.image.vendor": "Strukturpiloten OHG",
            "org.opencontainers.image.version": "1.0.0"
        }
    }
}
