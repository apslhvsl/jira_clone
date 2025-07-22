import React, { useEffect, useState, useContext } from 'react';
import { ProjectContext } from '../context/ProjectContext';
import ProjectMembers from '../components/ProjectMembers';
import ProjectTasks from '../components/ProjectTasks';
import { Row, Col, Card, Statistic, Progress, List, Spin, message } from 'antd';
import { CheckCircleOutlined, ProjectOutlined, TeamOutlined, PlusOutlined } from '@ant-design/icons';
import { Button, Modal, Form, Input, Select, DatePicker, Alert, Space } from 'antd';

function Dashboard() {
  const { selectedProject } = useContext(ProjectContext);
  const [stats, setStats] = useState({ projectCount: 0, taskCount: 0, teamCount: 0 });
  const [activity, setActivity] = useState([]);
  const [myTasks, setMyTasks] = useState([]);
  const [projectProgress, setProjectProgress] = useState({ completed: 0, in_progress: 0, todo: 0, total: 0 });
  const [loading, setLoading] = useState(true);
  const [showTaskModal, setShowTaskModal] = useState(false);
  const [taskForm] = Form.useForm();
  const [taskError, setTaskError] = useState('');
  const [users, setUsers] = useState([]);
  const [columns, setColumns] = useState([]);
  const [allProjects, setAllProjects] = useState([]);
  const [selectedTaskProject, setSelectedTaskProject] = useState(null);
  const [taskType, setTaskType] = useState('task');
  const [epics, setEpics] = useState([]);
  const user = JSON.parse(localStorage.getItem('user') || '{}');
  const [projectMembers, setProjectMembers] = useState([]);
  const [invitations, setInvitations] = useState([]);
  const [invLoading, setInvLoading] = useState(false);
  const [invActionLoading, setInvActionLoading] = useState({});

  useEffect(() => {
    const fetchDashboardData = async () => {
      setLoading(true);
      const token = localStorage.getItem('token');
      try {
        // Fetch stats
        const statsRes = await fetch('http://localhost:5000/dashboard/stats', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (statsRes.ok) {
          const data = await statsRes.json();
          setStats(data);
        }
        // Fetch activity log
        const activityRes = await fetch('http://localhost:5000/items/activity', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (activityRes.ok) {
          const data = await activityRes.json();
          setActivity(data.activity || []);
        }
        // Fetch my tasks
        const myTasksRes = await fetch('http://localhost:5000/items/my-tasks', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (myTasksRes.ok) {
          const data = await myTasksRes.json();
          setMyTasks(data.tasks || []);
        }
        // Fetch all projects for Add Task modal
        const projectsRes = await fetch('http://localhost:5000/projects', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (projectsRes.ok) {
          const data = await projectsRes.json();
          setAllProjects(data.projects || []);
        }
        // Fetch project progress
        if (selectedProject) {
          const progressRes = await fetch(`http://localhost:5000/projects/${selectedProject.id}/progress`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          if (progressRes.ok) {
            const data = await progressRes.json();
            setProjectProgress({
              ...data,
              total: data.total || 0
            });
          }
        } else {
          setProjectProgress({ completed: 0, in_progress: 0, todo: 0, total: 0 });
        }
      } catch (err) {
        message.error('Failed to load dashboard data');
      }
      setLoading(false);
    };
    fetchDashboardData();
    if (selectedProject) {
      fetchUsers();
      fetchColumns();
      fetchProjectMembers();
    }
  }, [selectedProject]);

  useEffect(() => {
    fetchInvitations();
  }, []);

  const fetchInvitations = async () => {
    setInvLoading(true);
    const token = localStorage.getItem('token');
    try {
      const res = await fetch('http://localhost:5000/my-invitations', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setInvitations(data.invitations || []);
      }
    } catch {
      setInvitations([]);
    }
    setInvLoading(false);
  };

  const handleInvitationAction = async (inviteId, projectId, action) => {
    setInvActionLoading(l => ({ ...l, [inviteId]: true }));
    const token = localStorage.getItem('token');
    try {
      const res = await fetch(`http://localhost:5000/projects/${projectId}/invitation/${inviteId}/${action}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setInvitations(inv => inv.filter(i => i.id !== inviteId));
        message.success(`Invitation ${action}ed successfully.`);
      } else {
        message.error('Failed to update invitation');
      }
    } catch {
      message.error('Network error');
    }
    setInvActionLoading(l => ({ ...l, [inviteId]: false }));
  };

  // Fetch columns and users for the selected project in the Add Task modal
  useEffect(() => {
    if (!selectedTaskProject) return;
    const fetchForProject = async () => {
      const token = localStorage.getItem('token');
      // Fetch columns
      const colRes = await fetch(`http://localhost:5000/projects/${selectedTaskProject}/columns`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (colRes.ok) {
        const data = await colRes.json();
        setColumns(data.columns || []);
      }
      // Fetch users
      const userRes = await fetch(`http://localhost:5000/projects/${selectedTaskProject}/members`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (userRes.ok) {
        const data = await userRes.json();
        setUsers(data.members || []);
      }
      // Fetch epics
      const epicsRes = await fetch(`http://localhost:5000/items/projects/${selectedTaskProject}/items`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (epicsRes.ok) {
        const data = await epicsRes.json();
        setEpics((data.items || []).filter(i => i.type && i.type.toLowerCase() === 'epic'));
      }
    };
    fetchForProject();
  }, [selectedTaskProject]);

  const fetchUsers = async () => {
    const token = localStorage.getItem('token');
    const res = await fetch(`http://localhost:5000/projects/${selectedProject.id}/members`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const data = await res.json();
    if (res.ok) setUsers(data.members);
  };

  const fetchColumns = async () => {
    const token = localStorage.getItem('token');
    const res = await fetch(`http://localhost:5000/projects/${selectedProject.id}/columns`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (res.ok) {
      const data = await res.json();
      setColumns(data.columns);
    }
  };

  const fetchProjectMembers = async () => {
    const token = localStorage.getItem('token');
    const res = await fetch(`http://localhost:5000/projects/${selectedProject.id}/members`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (res.ok) {
      const data = await res.json();
      setProjectMembers(data.members || []);
    }
  };

  const myProjectRole = projectMembers.find(m => m.user_id === user.id)?.role;
  const canAddTask = myProjectRole === 'admin' || myProjectRole === 'manager' || myProjectRole === 'member';

  const handleTaskSubmit = async (values) => {
    setTaskError('');
    const token = localStorage.getItem('token');
    let columnId = undefined;
    if (columns && columns.length > 0) {
      const todoCol = columns.find(col => (col.status || col.name.toLowerCase().replace(/\s/g, '')) === 'todo');
      columnId = todoCol ? todoCol.id : columns[0].id;
    }
    if (!columnId) {
      setTaskError('No columns found for this project.');
      return;
    }
    if (!selectedTaskProject) {
      setTaskError('Please select a project.');
      return;
    }
    const payload = { ...values, type: taskType, column_id: columnId };
    if (payload.due_date && typeof payload.due_date === 'object' && payload.due_date.format) {
      payload.due_date = payload.due_date.format('YYYY-MM-DD');
    }
    if (taskType !== 'epic' && values.parent_id) {
      payload.parent_id = values.parent_id;
    }
    const res = await fetch(`http://localhost:5000/items/projects/${selectedTaskProject}/items`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      setShowTaskModal(false);
      taskForm.resetFields();
      setSelectedTaskProject(null);
      setTaskType('task');
      // Optionally, trigger ProjectTasks to refresh
      window.dispatchEvent(new Event('taskCreated'));
    } else {
      const data = await res.json();
      setTaskError(data.error || 'Failed to create task');
    }
  };

  if (loading) {
    return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}><Spin size="large" /></div>;
  }

  return (
    <div style={{ maxWidth: 1200, margin: '32px auto', padding: '0 16px' }}>
      {/* --- Pending Invitations --- */}
      {invitations.length > 0 && (
        <Card style={{ marginBottom: 24 }}>
          <h3>Pending Project Invitations</h3>
          {invLoading ? <Spin /> : (
            <List
              bordered
              dataSource={invitations}
              renderItem={inv => (
                <List.Item
                  actions={[
                    <Button
                      size="small"
                      type="primary"
                      loading={invActionLoading[inv.id]}
                      onClick={() => handleInvitationAction(inv.id, inv.project_id, 'accept')}
                    >Accept</Button>,
                    <Button
                      size="small"
                      danger
                      loading={invActionLoading[inv.id]}
                      onClick={() => handleInvitationAction(inv.id, inv.project_id, 'reject')}
                    >Reject</Button>
                  ]}
                >
                  <List.Item.Meta
                    title={<span>Project ID: {inv.project_id}</span>}
                    description={`Invited at ${new Date(inv.created_at).toLocaleString()}`}
                  />
                </List.Item>
              )}
            />
          )}
        </Card>
      )}
      {selectedProject && canAddTask && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setShowTaskModal(true)}>
            Add Task
          </Button>
        </div>
      )}
      <Row gutter={[24, 24]}>
        <Col xs={24} sm={8}>
          <Card bordered={false} style={{ background: '#e6f4ff' }}>
            <Statistic title="Projects" value={stats.projectCount} prefix={<ProjectOutlined />} valueStyle={{ color: '#1677ff' }} />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card bordered={false} style={{ background: '#f6ffed' }}>
            <Statistic title="Tasks" value={stats.taskCount} prefix={<CheckCircleOutlined />} valueStyle={{ color: '#52c41a' }} />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card bordered={false} style={{ background: '#fffbe6' }}>
            <Statistic title="Teams" value={stats.teamCount} prefix={<TeamOutlined />} valueStyle={{ color: '#faad14' }} />
          </Card>
        </Col>
      </Row>
      <style>{`
        .dashboard-hide-scrollbar::-webkit-scrollbar { display: none; }
      `}</style>
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        <Col xs={24} sm={12}>
          <Card title="My Tasks" bordered={false} style={{ height: 340, display: 'flex', flexDirection: 'column' }}>
            <List
              dataSource={myTasks}
              renderItem={task => (
                <List.Item>
                  <span>{task.title}</span>
                  <span style={{ marginLeft: 8, padding: '2px 8px', borderRadius: 4, background: task.status === 'done' ? '#f6ffed' : '#f0f0f0', color: task.status === 'done' ? '#52c41a' : '#888', fontWeight: 500, fontSize: 12 }}>{task.status}</span>
                </List.Item>
              )}
              locale={{ emptyText: 'No tasks assigned to you' }}
              style={{ maxHeight: 260, overflowY: 'auto', minHeight: 0, scrollbarWidth: 'none', msOverflowStyle: 'none' }}
              className="dashboard-hide-scrollbar"
            />
          </Card>
        </Col>
        <Col xs={24} sm={12}>
          <Card title="Activity Feed" bordered={false} style={{ height: 340, display: 'flex', flexDirection: 'column' }}>
            <List
              dataSource={activity}
              renderItem={log => (
                <List.Item>
                  <span style={{ fontWeight: 500 }}>{log.user}</span> {log.action} <span style={{ color: '#888' }}>{log.details}</span> <span style={{ color: '#bbb', fontSize: 12 }}>{log.created_at ? new Date(log.created_at).toLocaleString() : ''}</span>
                </List.Item>
              )}
              locale={{ emptyText: 'No recent activity' }}
              style={{ maxHeight: 260, overflowY: 'auto', minHeight: 0, scrollbarWidth: 'none', msOverflowStyle: 'none' }}
              className="dashboard-hide-scrollbar"
            />
          </Card>
        </Col>
      </Row>
      <Modal
        open={showTaskModal}
        title="Add Task"
        onCancel={() => { setShowTaskModal(false); setSelectedTaskProject(null); }}
        onOk={() => taskForm.submit()}
        destroyOnClose
      >
        <Form form={taskForm} layout="vertical" onFinish={handleTaskSubmit}>
          <Form.Item label="Project" name="project_id" rules={[{ required: true, message: 'Please select a project' }]}>
            <Select
              showSearch
              placeholder="Select a project"
              optionFilterProp="children"
              onChange={val => { setSelectedTaskProject(val); taskForm.setFieldsValue({ parent_id: undefined }); }}
              value={selectedTaskProject}
              filterOption={(input, option) =>
                option.children.toLowerCase().indexOf(input.toLowerCase()) >= 0
              }
            >
              {allProjects.map(p => (
                <Select.Option key={p.id} value={p.id}>{p.name}</Select.Option>
              ))}
            </Select>
          </Form.Item>
          <Form.Item label="Type" name="type" initialValue="task" rules={[{ required: true, message: 'Please select a type' }]}>
            <Select value={taskType} onChange={val => { setTaskType(val); taskForm.setFieldsValue({ parent_id: undefined }); }}>
              <Select.Option value="epic">Epic</Select.Option>
              <Select.Option value="task">Task</Select.Option>
              <Select.Option value="bug">Bug</Select.Option>
              <Select.Option value="feature">Feature</Select.Option>
            </Select>
          </Form.Item>
          {taskType !== 'epic' && (
            <Form.Item label="Parent Epic" name="parent_id">
              <Select allowClear placeholder="Select an epic">
                {epics.map(e => (
                  <Select.Option key={e.id} value={e.id}>{e.title}</Select.Option>
                ))}
              </Select>
            </Form.Item>
          )}
          <Form.Item label="Title" name="title" rules={[{ required: true, message: 'Title is required' }]}>
            <Input />
          </Form.Item>
          <Form.Item label="Description" name="description">
            <Input.TextArea autoSize={{ minRows: 2, maxRows: 4 }} />
          </Form.Item>
          <Form.Item label="Priority" name="priority">
            <Select allowClear>
              <Select.Option value="High">High</Select.Option>
              <Select.Option value="Medium">Medium</Select.Option>
              <Select.Option value="Low">Low</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item label="Assignee" name="assignee_id">
            <Select allowClear showSearch optionFilterProp="children" placeholder="Assign to...">
              {users.map(m => (
                <Select.Option key={m.user_id} value={m.user_id}>{m.username || m.email}</Select.Option>
              ))}
            </Select>
          </Form.Item>
          <Form.Item label="Due Date" name="due_date">
            <DatePicker style={{ width: '100%' }} />
          </Form.Item>
          {taskError && <Alert message={taskError} type="error" showIcon style={{ marginBottom: 12 }} />}
        </Form>
      </Modal>
    </div>
  );
}

export default Dashboard;
