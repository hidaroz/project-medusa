"""
Unit tests for approval gate system

Tests risk assessment and approval logic
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from medusa.approval import ApprovalGate, Action, RiskLevel


@pytest.mark.unit
class TestRiskLevel:
    """Test RiskLevel enum"""
    
    def test_risk_levels_exist(self):
        """Test that all risk levels are defined"""
        assert RiskLevel.LOW
        assert RiskLevel.MEDIUM
        assert RiskLevel.HIGH
        assert RiskLevel.CRITICAL
    
    def test_risk_level_values(self):
        """Test risk level values"""
        assert RiskLevel.LOW.value == "LOW"
        assert RiskLevel.MEDIUM.value == "MEDIUM"
        assert RiskLevel.HIGH.value == "HIGH"
        assert RiskLevel.CRITICAL.value == "CRITICAL"


@pytest.mark.unit
class TestAction:
    """Test Action dataclass"""
    
    def test_action_creation(self):
        """Test creating an Action instance"""
        action = Action(
            command="nmap -sV localhost",
            technique_id="T1046",
            technique_name="Network Service Discovery",
            risk_level=RiskLevel.LOW,
            impact_description="Safe port scan"
        )
        assert action.command == "nmap -sV localhost"
        assert action.technique_id == "T1046"
        assert action.risk_level == RiskLevel.LOW
        assert action.reversible is True  # Default value
    
    def test_action_with_all_fields(self):
        """Test Action with all optional fields"""
        action = Action(
            command="sqlmap --dump",
            technique_id="T1190",
            technique_name="Exploitation",
            risk_level=RiskLevel.HIGH,
            impact_description="Database extraction",
            target="http://target.com",
            reversible=False,
            data_at_risk="User database"
        )
        assert action.target == "http://target.com"
        assert action.reversible is False
        assert action.data_at_risk == "User database"


@pytest.mark.unit
class TestApprovalGate:
    """Test ApprovalGate approval logic"""
    
    @pytest.fixture
    def mock_config(self):
        """Create mock configuration"""
        config = Mock()
        config.get = Mock(return_value={
            "auto_approve_low": True,
            "auto_approve_medium": False,
            "auto_approve_high": False
        })
        return config
    
    @pytest.fixture
    def approval_gate(self, mock_config):
        """Create ApprovalGate instance with mocked config"""
        with patch('medusa.approval.get_config', return_value=mock_config):
            gate = ApprovalGate()
        return gate
    
    def test_initialization(self, approval_gate):
        """Test ApprovalGate initializes correctly"""
        assert approval_gate.approved_all is False
        assert approval_gate.aborted is False
    
    def test_should_auto_approve_low_risk(self, approval_gate):
        """Test LOW risk actions are auto-approved by default"""
        result = approval_gate.should_auto_approve(RiskLevel.LOW)
        assert result is True
    
    def test_should_not_auto_approve_medium_risk(self, approval_gate):
        """Test MEDIUM risk actions require approval by default"""
        result = approval_gate.should_auto_approve(RiskLevel.MEDIUM)
        assert result is False
    
    def test_should_not_auto_approve_high_risk(self, approval_gate):
        """Test HIGH risk actions require approval"""
        result = approval_gate.should_auto_approve(RiskLevel.HIGH)
        assert result is False
    
    def test_should_never_auto_approve_critical(self, approval_gate):
        """Test CRITICAL risk actions never auto-approve"""
        result = approval_gate.should_auto_approve(RiskLevel.CRITICAL)
        assert result is False
    
    @pytest.mark.parametrize("risk_level,expected", [
        (RiskLevel.LOW, True),
        (RiskLevel.MEDIUM, False),
        (RiskLevel.HIGH, False),
        (RiskLevel.CRITICAL, False),
    ])
    def test_auto_approve_by_risk_level(self, approval_gate, risk_level, expected):
        """Test auto-approval for different risk levels"""
        result = approval_gate.should_auto_approve(risk_level)
        assert result == expected
    
    def test_approve_all_flag(self, approval_gate):
        """Test that approve_all flag overrides auto-approval"""
        approval_gate.approved_all = True
        
        # Even CRITICAL should return True when approved_all is set
        assert approval_gate.should_auto_approve(RiskLevel.CRITICAL) is True
        assert approval_gate.should_auto_approve(RiskLevel.HIGH) is True
    
    @patch('medusa.approval.console')
    def test_request_approval_auto_approved(self, mock_console, approval_gate, low_risk_action):
        """Test requesting approval for auto-approved action"""
        result = approval_gate.request_approval(low_risk_action)
        
        assert result is True
        mock_console.print.assert_called_once()
    
    @patch('medusa.approval.Prompt.ask')
    @patch('medusa.approval.console')
    def test_request_approval_user_approves(self, mock_console, mock_prompt, approval_gate, high_risk_action):
        """Test user manually approving high-risk action"""
        mock_prompt.return_value = "y"
        
        result = approval_gate.request_approval(high_risk_action)
        
        assert result is True
        mock_prompt.assert_called_once()
    
    @patch('medusa.approval.Prompt.ask')
    @patch('medusa.approval.console')
    def test_request_approval_user_denies(self, mock_console, mock_prompt, approval_gate, high_risk_action):
        """Test user denying high-risk action"""
        mock_prompt.return_value = "n"
        
        result = approval_gate.request_approval(high_risk_action)
        
        assert result is False
    
    @patch('medusa.approval.Prompt.ask')
    @patch('medusa.approval.console')
    def test_request_approval_user_skips(self, mock_console, mock_prompt, approval_gate, high_risk_action):
        """Test user skipping action"""
        mock_prompt.return_value = "s"
        
        result = approval_gate.request_approval(high_risk_action)
        
        assert result is False
    
    @patch('medusa.approval.Prompt.ask')
    @patch('medusa.approval.console')
    def test_request_approval_user_aborts(self, mock_console, mock_prompt, approval_gate, high_risk_action):
        """Test user aborting operation"""
        mock_prompt.return_value = "a"
        
        result = approval_gate.request_approval(high_risk_action)
        
        assert result is False
        assert approval_gate.aborted is True
    
    @patch('medusa.approval.Prompt.ask')
    @patch('medusa.approval.console')
    def test_request_approval_approve_all(self, mock_console, mock_prompt, approval_gate, high_risk_action):
        """Test user choosing approve all"""
        mock_prompt.return_value = "all"
        
        result = approval_gate.request_approval(high_risk_action)
        
        assert result is True
        assert approval_gate.approved_all is True
    
    def test_aborted_blocks_subsequent_requests(self, approval_gate, low_risk_action):
        """Test that aborted flag blocks all subsequent approval requests"""
        approval_gate.aborted = True
        
        result = approval_gate.request_approval(low_risk_action)
        
        assert result is False
    
    def test_reset(self, approval_gate):
        """Test reset clears approval state"""
        approval_gate.approved_all = True
        approval_gate.aborted = True
        
        approval_gate.reset()
        
        assert approval_gate.approved_all is False
        assert approval_gate.aborted is False
    
    def test_is_aborted(self, approval_gate):
        """Test is_aborted method"""
        assert approval_gate.is_aborted() is False
        
        approval_gate.aborted = True
        assert approval_gate.is_aborted() is True
    
    @patch('medusa.approval.console')
    def test_display_approval_prompt_low_risk(self, mock_console, approval_gate, low_risk_action):
        """Test display of LOW risk approval prompt"""
        approval_gate._display_approval_prompt(low_risk_action)
        
        # Verify console.print was called with a Panel
        assert mock_console.print.called
    
    @patch('medusa.approval.console')
    def test_display_approval_prompt_critical_risk(self, mock_console, approval_gate, critical_risk_action):
        """Test display of CRITICAL risk approval prompt with warnings"""
        approval_gate._display_approval_prompt(critical_risk_action)
        
        assert mock_console.print.called
    
    def test_get_user_choice_mappings(self, approval_gate):
        """Test user choice mappings"""
        assert approval_gate._get_user_choice(None) == "deny"  # Default
        
        # Test various input mappings
        test_cases = [
            ("y", "approve"),
            ("yes", "approve"),
            ("n", "deny"),
            ("no", "deny"),
            ("s", "skip"),
            ("skip", "skip"),
            ("a", "abort"),
            ("abort", "abort"),
            ("all", "approve_all"),
        ]
        
        for user_input, expected in test_cases:
            # Mock the Prompt.ask to return user_input
            with patch('medusa.approval.Prompt.ask', return_value=user_input):
                # Create a mock action for testing
                mock_action = Mock()
                choice = approval_gate._get_user_choice(mock_action)
                assert choice == expected, f"Expected {expected} for input {user_input}, got {choice}"


@pytest.mark.unit
class TestApprovalGateIntegration:
    """Integration tests for multiple approval requests"""
    
    @patch('medusa.approval.Prompt.ask')
    @patch('medusa.approval.console')
    def test_multiple_approvals_with_approve_all(self, mock_console, mock_prompt, mock_config):
        """Test multiple approvals after approve_all is set"""
        with patch('medusa.approval.get_config', return_value=mock_config):
            gate = ApprovalGate()
        
        mock_prompt.return_value = "all"
        
        # First high-risk action - user chooses "approve all"
        action1 = Action(
            command="test1",
            technique_id="T1190",
            technique_name="Test",
            risk_level=RiskLevel.HIGH,
            impact_description="Test"
        )
        result1 = gate.request_approval(action1)
        assert result1 is True
        assert gate.approved_all is True
        
        # Second high-risk action - should auto-approve
        action2 = Action(
            command="test2",
            technique_id="T1190",
            technique_name="Test",
            risk_level=RiskLevel.HIGH,
            impact_description="Test"
        )
        result2 = gate.request_approval(action2)
        assert result2 is True
        
        # Prompt should only be called once
        assert mock_prompt.call_count == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

