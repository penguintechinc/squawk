#!/usr/bin/env python3
"""
Unit tests for installer functionality
"""

import pytest
import sys
import os
import platform
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from install import SquawkInstaller

class TestSquawkInstaller:
    """Test the SquawkInstaller class"""
    
    @pytest.fixture
    def installer(self):
        """Create an installer instance for testing"""
        with patch.object(SquawkInstaller, 'check_admin_privileges', return_value=True):
            return SquawkInstaller()
    
    def test_check_admin_windows(self):
        """Test admin check on Windows"""
        import ctypes
        from unittest.mock import MagicMock

        # ctypes.windll only exists on Windows — attach a mock (create=True)
        # so the Windows code path is exercisable on Linux/macOS CI.
        windll = MagicMock()
        windll.shell32.IsUserAnAdmin.return_value = 1
        with patch('platform.system', return_value='Windows'):
            with patch.object(ctypes, 'windll', windll, create=True):
                installer = SquawkInstaller()
                assert installer.is_admin is True
    
    def test_check_admin_unix(self):
        """Test admin check on Unix systems"""
        with patch('platform.system', return_value='Linux'):
            with patch('os.geteuid', return_value=0):
                installer = SquawkInstaller()
                assert installer.is_admin is True
            
            with patch('os.geteuid', return_value=1000):
                installer = SquawkInstaller()
                assert installer.is_admin is False
    
    def test_get_install_path_windows(self):
        """Test install path on Windows"""
        with patch('platform.system', return_value='Windows'):
            installer = SquawkInstaller()
            assert 'Squawk' in str(installer.install_path)
    
    def test_get_install_path_macos(self):
        """Test install path on macOS"""
        with patch('platform.system', return_value='Darwin'):
            installer = SquawkInstaller()
            assert installer.install_path == Path('/usr/local/squawk')
    
    def test_get_install_path_linux(self):
        """Test install path on Linux"""
        with patch('platform.system', return_value='Linux'):
            installer = SquawkInstaller()
            assert installer.install_path == Path('/opt/squawk')
    
    def test_create_directories(self, installer):
        """Test directory creation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            installer.install_path = Path(tmpdir) / 'install'
            installer.config_path = Path(tmpdir) / 'config'
            
            installer.create_directories()
            
            assert installer.install_path.exists()
            assert installer.config_path.exists()
            assert (installer.install_path / 'logs').exists()
    
    @patch('subprocess.run')
    def test_install_dependencies(self, mock_run, installer):
        """Test dependency installation"""
        installer.install_dependencies()
        
        # Check that pip install was called for each dependency
        assert mock_run.called
        calls = mock_run.call_args_list
        
        # Should install multiple packages
        assert len(calls) >= 6  # At least 6 dependencies
        
        # Check that pip install command is correct
        for call in calls:
            args = call[0][0]
            assert args[0] == sys.executable
            assert args[1] == '-m'
            assert args[2] == 'pip'
            assert args[3] == 'install'
    
    def test_create_config(self, installer):
        """Test configuration file creation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            installer.config_path = Path(tmpdir)
            
            with patch.dict(os.environ, {
                'SQUAWK_SERVER_URL': 'https://test.server',
                'SQUAWK_AUTH_TOKEN': 'test-token',
                'CACHE_TTL': '600'
            }):
                config_file = installer.create_config()
            
            assert config_file.exists()
            
            # Read and verify config
            import yaml
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            assert config['dns_server_url'] == 'https://test.server'
            assert config['auth_token'] == 'test-token'
            assert config['cache_ttl'] == 600
    
    @patch('subprocess.run')
    def test_install_windows_service(self, mock_run, installer):
        """Test Windows service installation"""
        with patch('platform.system', return_value='Windows'):
            with tempfile.TemporaryDirectory() as tmpdir:
                installer.install_path = Path(tmpdir)
                installer.config_path = Path(tmpdir)
                
                installer.install_windows_service()
                
                # Check that service script was created
                service_script = installer.install_path / 'service.py'
                assert service_script.exists()
                
                # Check that subprocess commands were called
                assert mock_run.called
    
    @patch('subprocess.run')
    def test_install_macos_daemon(self, mock_run):
        """Test macOS daemon installation"""
        with patch('platform.system', return_value='Darwin'):
            installer = SquawkInstaller()
            
            with tempfile.TemporaryDirectory() as tmpdir:
                installer.install_path = Path(tmpdir)
                installer.config_path = Path(tmpdir)
                
                with patch('builtins.open', create=True) as mock_open:
                    with patch('os.chown'):
                        with patch('os.chmod'):
                            installer.install_macos_daemon()
                
                # Check that launchctl was called
                mock_run.assert_called()
    
    @patch('subprocess.run')
    def test_install_systemd_service(self, mock_run):
        """Test systemd service installation"""
        with patch('platform.system', return_value='Linux'):
            installer = SquawkInstaller()
            
            with tempfile.TemporaryDirectory() as tmpdir:
                installer.install_path = Path(tmpdir)
                installer.config_path = Path(tmpdir)
                
                with patch('builtins.open', create=True) as mock_open:
                    installer.install_systemd_service()
                
                # Check that systemctl commands were called
                assert mock_run.called
                calls = [str(call) for call in mock_run.call_args_list]
                
                # Should reload systemd and enable service
                assert any('daemon-reload' in str(call) for call in calls)
                assert any('enable' in str(call) for call in calls)
    
    @patch('subprocess.run')
    def test_configure_system_dns_windows(self, mock_run):
        """Test DNS configuration on Windows"""
        with patch('platform.system', return_value='Windows'):
            installer = SquawkInstaller()
            installer.configure_system_dns()
            
            # Check that netsh commands were called
            assert mock_run.called
            calls = [str(call) for call in mock_run.call_args_list]
            assert any('netsh' in str(call) for call in calls)
    
    @patch('subprocess.run')
    def test_configure_system_dns_macos(self, mock_run):
        """Test DNS configuration on macOS"""
        with patch('platform.system', return_value='Darwin'):
            installer = SquawkInstaller()
            
            # Mock networksetup output
            mock_run.return_value.stdout = "Wi-Fi\nEthernet\n"
            
            installer.configure_system_dns()
            
            # Check that networksetup commands were called
            assert mock_run.called
            calls = [str(call) for call in mock_run.call_args_list]
            assert any('networksetup' in str(call) for call in calls)
    
    def test_configure_system_dns_linux(self):
        """Test DNS configuration on Linux"""
        with patch('platform.system', return_value='Linux'):
            installer = SquawkInstaller()
            
            with tempfile.TemporaryDirectory() as tmpdir:
                # Test with systemd-resolved
                with patch('pathlib.Path.exists', return_value=True):
                    with patch('builtins.open', create=True) as mock_open:
                        with patch('subprocess.run') as mock_run:
                            installer.configure_system_dns()
                            
                            # Should restart systemd-resolved
                            mock_run.assert_called()
                
                # Test with traditional resolv.conf
                with patch('pathlib.Path.exists', return_value=False):
                    with patch('builtins.open', create=True) as mock_open:
                        with patch('shutil.copy'):
                            installer.configure_system_dns()
                            
                            # Should write to resolv.conf
                            mock_open.assert_called()
    
    @patch('subprocess.run')
    def test_start_service(self, mock_run, installer):
        """Test service starting"""
        # Test Windows
        with patch.object(installer, 'system', 'Windows'):
            installer.start_service()
            mock_run.assert_called_with(['net', 'start', 'SquawkDNS'], check=False)
        
        # Test macOS
        with patch.object(installer, 'system', 'Darwin'):
            installer.start_service()
            mock_run.assert_called_with(['launchctl', 'start', 'com.squawk.dns'], check=False)
        
        # Test Linux
        with patch.object(installer, 'system', 'Linux'):
            installer.start_service()
            mock_run.assert_called_with(['systemctl', 'start', 'squawk-dns.service'], check=False)